#!/usr/bin/env sh
set -eu

test "${PUSH:-}" = "false"
test -f "$CONFIG_FILE"
case "${IMAGE_TAG:-}" in
  ''|'__IMAGE_TAG__') exit 2 ;;
esac
printf '%s\n' 'fixture docker official push passed'
