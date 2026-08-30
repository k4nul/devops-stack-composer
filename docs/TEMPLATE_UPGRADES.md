# Template upgrades

Template pins never advance during normal composition. Upgrades are a separate
preview, review, validation, and write workflow.

## Inspect current resolution

```sh
devops-stack templates list --project .
devops-stack templates list --project . --json
devops-stack doctor --project . --remote
```

`templates list` resolves all sources and exits non-zero if any commit differs from
the lock. `doctor --remote` also checks remote access and reports which remote `main`
branches differ.

## Preview an update

```sh
devops-stack templates update --project .
devops-stack templates update --project . --json
```

The command runs `git ls-remote --heads <repository> main` for each template and shows
the current and candidate full commits. When a pin differs, both commits are fetched
into temporary directories and checked for the exact commit, required interface
markers, and declared `LICENSE`. Preview can therefore perform network reads, but it
does not modify the lock, persistent cache, or any source checkout.

Review upstream changes before writing. In particular, compare required marker files,
official input keys, JSON plan shape, command parameters, validation semantics,
license, and release notes. A candidate reaching remote `main` is not by itself
evidence of adapter compatibility.

## Write and verify

```sh
devops-stack templates update --project . --write
git diff -- templates.lock.json
devops-stack templates list --project .
devops-stack generate --project .
devops-stack diff --project . --against generated
python3 -m unittest discover -s tests -v
```

`--write` persists the already verified candidate commits by atomically replacing the
project lock. If the loaded lock changes during the same-target operation, the command
refuses to overwrite the concurrent edit.

The updater changes the commit and review date. It does not automatically change the
adapter or interface schema version and does not claim tests passed. If an upstream
contract changed, update the adapter, tests, marker list, schema version, and docs in
one reviewed logical change.

After generating and reviewing the preview, write and verify an example tree:

```sh
devops-stack generate --project examples/python-service --write
devops-stack validate --project examples/python-service
devops-stack report --project examples/python-service
```

If reports already exist, inspect them and use `report --force` only when replacement
is intended. If generated output contains a stale path from the old adapter, remove
that path manually after review; generation never deletes it automatically.

## Offline and local testing

Use explicit checkouts to test candidates without changing the lock only after first
editing a temporary lock to the candidate SHA:

```sh
devops-stack generate --project . \
  --lock path/to/review.lock.json \
  --template docker=/path/to/docker-build-template \
  --template jenkins=/path/to/jenkins-pipeline-template \
  --template kubernetes=/path/to/k8s-platform-template \
  --no-fetch
```

An explicit path does not bypass the lock: its `HEAD` must equal the pin. `--no-fetch`
only prevents the final network fetch and is useful for reproducible offline checks.

## Rollback

Restore the previous reviewed lock entry in a normal commit, or revert the lock update
commit, then regenerate and validate. Do not force a mismatching checkout, rewrite
published history, or manually change only the generated manifest. Generated
artifacts must be reproduced from the restored configuration and pins.
