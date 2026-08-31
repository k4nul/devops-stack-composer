#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <empty-install-directory> [archive-cache-directory]" >&2
  exit 2
fi

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) ;;
  *)
    echo "error: the pinned CI tool bundle supports Linux x86_64 only" >&2
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
  echo "error: refusing to install tools into the filesystem root" >&2
  exit 2
fi
for executable in gh kind kubectl kubeconform syft trivy; do
  if [[ -e "$install_directory/$executable" || -L "$install_directory/$executable" ]]; then
    echo "error: install target already exists: $executable" >&2
    exit 2
  fi
done

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
    echo "error: refusing to cache tools in the filesystem root" >&2
    exit 2
  fi
else
  cache_directory=$working_directory
fi

download() {
  local url=$1
  local output=$2
  local expected_sha256=$3
  local partial="$output.partial.$$"

  if [[ -f "$output" && ! -L "$output" ]] &&
    printf '%s  %s\n' "$expected_sha256" "$output" | sha256sum --check --status; then
    return
  fi
  rm -f -- "$output" "$partial"
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
    "$url"
  printf '%s  %s\n' "$expected_sha256" "$partial" | sha256sum --check --status
  mv -- "$partial" "$output"
}

download \
  "https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64" \
  "$cache_directory/kind-linux-amd64" \
  "aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d"
download \
  "https://dl.k8s.io/release/v1.36.4/bin/linux/amd64/kubectl" \
  "$cache_directory/kubectl-linux-amd64" \
  "8b8f088da2dab964f853b38464033b1be15ede2839eca751482357c45abdd05a"
download \
  "https://github.com/yannh/kubeconform/releases/download/v0.8.0/kubeconform-linux-amd64.tar.gz" \
  "$cache_directory/kubeconform-linux-amd64.tar.gz" \
  "9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883"
download \
  "https://github.com/anchore/syft/releases/download/v1.51.1/syft_1.51.1_linux_amd64.tar.gz" \
  "$cache_directory/syft_1.51.1_linux_amd64.tar.gz" \
  "8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3"
download \
  "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz" \
  "$cache_directory/trivy_0.74.0_Linux-64bit.tar.gz" \
  "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"
download \
  "https://github.com/cli/cli/releases/download/v2.95.0/gh_2.95.0_linux_amd64.tar.gz" \
  "$cache_directory/gh_2.95.0_linux_amd64.tar.gz" \
  "25d1e4729e8808c9ed3d613e96ebd3f3e44446f2d368c89d878a71a36ddb3d8c"

install -m 0755 "$cache_directory/kind-linux-amd64" "$install_directory/kind"
install -m 0755 "$cache_directory/kubectl-linux-amd64" "$install_directory/kubectl"

for executable in kubeconform syft trivy; do
  case "$executable" in
    kubeconform) archive=kubeconform-linux-amd64.tar.gz ;;
    syft) archive=syft_1.51.1_linux_amd64.tar.gz ;;
    trivy) archive=trivy_0.74.0_Linux-64bit.tar.gz ;;
  esac
  extraction_directory="$working_directory/$executable-extracted"
  mkdir "$extraction_directory"
  tar \
    --extract \
    --file "$cache_directory/$archive" \
    --gzip \
    --directory "$extraction_directory" \
    "$executable"
  install -m 0755 "$extraction_directory/$executable" "$install_directory/$executable"
done

mkdir "$working_directory/gh-extracted"
tar \
  --extract \
  --file "$cache_directory/gh_2.95.0_linux_amd64.tar.gz" \
  --gzip \
  --directory "$working_directory/gh-extracted" \
  "gh_2.95.0_linux_amd64/bin/gh"
install \
  -m 0755 \
  "$working_directory/gh-extracted/gh_2.95.0_linux_amd64/bin/gh" \
  "$install_directory/gh"

"$install_directory/gh" version
"$install_directory/kind" version
"$install_directory/kubectl" version --client
"$install_directory/kubeconform" -v
"$install_directory/syft" version
"$install_directory/trivy" version
