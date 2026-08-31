#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <empty-install-directory> [archive-cache-directory]" >&2
  exit 2
fi

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) ;;
  *)
    echo "error: the pinned actionlint installer supports Linux x86_64 only" >&2
    exit 2
    ;;
esac

install_directory=$1
if [[ -L "$install_directory" ]]; then
  echo "error: install directory must not be a symbolic link" >&2
  exit 2
fi
mkdir -p -- "$install_directory"
install_directory=$(cd "$install_directory" && pwd -P)
if [[ "$install_directory" == "/" ]]; then
  echo "error: refusing to install actionlint into the filesystem root" >&2
  exit 2
fi
if [[ -e "$install_directory/actionlint" || -L "$install_directory/actionlint" ]]; then
  echo "error: install target already exists: actionlint" >&2
  exit 2
fi

working_directory=$(mktemp -d)
trap 'rm -rf -- "$working_directory"' EXIT
if [[ $# -eq 2 ]]; then
  cache_directory=$2
  if [[ -L "$cache_directory" ]]; then
    echo "error: archive cache directory must not be a symbolic link" >&2
    exit 2
  fi
  mkdir -p -- "$cache_directory"
  cache_directory=$(cd "$cache_directory" && pwd -P)
  if [[ "$cache_directory" == "/" ]]; then
    echo "error: refusing to cache actionlint in the filesystem root" >&2
    exit 2
  fi
else
  cache_directory=$working_directory
fi

archive="$cache_directory/actionlint_1.7.12_linux_amd64.tar.gz"
expected_sha256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
if ! [[ -f "$archive" && ! -L "$archive" ]] ||
  ! printf '%s  %s\n' "$expected_sha256" "$archive" | sha256sum --check --status; then
  partial="$archive.partial.$$"
  rm -f -- "$archive" "$partial"
  curl \
    --fail \
    --location \
    --proto '=https' \
    --retry 3 \
    --retry-all-errors \
    --show-error \
    --silent \
    --tlsv1.2 \
    --output "$partial" \
    "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz"
  printf '%s  %s\n' "$expected_sha256" "$partial" | sha256sum --check --status
  mv -- "$partial" "$archive"
fi

tar \
  --extract \
  --file "$archive" \
  --gzip \
  --directory "$working_directory" \
  actionlint
install -m 0755 "$working_directory/actionlint" "$install_directory/actionlint"
"$install_directory/actionlint" -version
