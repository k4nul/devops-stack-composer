#!/usr/bin/env sh
set -eu

test "${PUSH:-}" = "false"
test -f "$CONFIG_FILE"
grep -Fx 'PLATFORMS=linux/amd64' "$CONFIG_FILE" >/dev/null
printf '%s\n' 'fixture docker local build passed'
