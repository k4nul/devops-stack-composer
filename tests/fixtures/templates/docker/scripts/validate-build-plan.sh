#!/usr/bin/env sh
set -eu

test "${PUSH:-}" = "false"
test -f "$CONFIG_FILE"
test -f application/app/server.py
test -f application/.dockerignore
test ! -e application/generated
test ! -e application/generated-preview
test ! -e application/.devops-stack
test -f generated/docker/Dockerfile
test -f generated/docker/Dockerfile.dockerignore
test -z "${DOCKER_ADAPTER_SECRET_SHOULD_NOT_LEAK:-}"
cmp -s generated/docker/Dockerfile.dockerignore application/.dockerignore

grep -Fx 'CONTEXT=application' "$CONFIG_FILE" >/dev/null
grep -Fx 'DOCKERFILE=generated/docker/Dockerfile' "$CONFIG_FILE" >/dev/null
grep -Fx 'PUSH=false' "$CONFIG_FILE" >/dev/null
grep -Fx 'SBOM=true' "$CONFIG_FILE" >/dev/null
grep -Fx 'PROVENANCE=mode=max' "$CONFIG_FILE" >/dev/null
grep -Fx '.git' application/.dockerignore >/dev/null
grep -Fx 'config/*.env' application/.dockerignore >/dev/null
grep -Fx 'generated' application/.dockerignore >/dev/null
grep -Fx '.devops-stack' application/.dockerignore >/dev/null
grep -F 'ARG OCI_CREATED=' generated/docker/Dockerfile >/dev/null
grep -F 'org.opencontainers.image.created="${OCI_CREATED}"' generated/docker/Dockerfile >/dev/null
grep -F 'USER 10001:10001' generated/docker/Dockerfile >/dev/null

mkdir -p "$(dirname -- "$BAKE_PLAN_OUTPUT")"
printf '%s\n' '{"fixture":"docker-template-validation"}' > "$BAKE_PLAN_OUTPUT"
printf '%s\n' 'fixture docker template validation passed'
