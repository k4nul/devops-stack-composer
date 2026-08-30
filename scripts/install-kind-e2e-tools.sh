#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <empty-install-directory>" >&2
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

download_directory=$(mktemp -d)
trap 'rm -rf -- "$download_directory"' EXIT

download() {
  local url=$1
  local output=$2
  local expected_sha256=$3
  curl \
    --fail \
    --location \
    --proto '=https' \
    --retry 3 \
    --retry-all-errors \
    --show-error \
    --silent \
    --tlsv1.2 \
    --output "$output" \
    "$url"
  printf '%s  %s\n' "$expected_sha256" "$output" | sha256sum --check --status
}

download \
  "https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64" \
  "$download_directory/kind" \
  "aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d"
download \
  "https://dl.k8s.io/release/v1.36.4/bin/linux/amd64/kubectl" \
  "$download_directory/kubectl" \
  "8b8f088da2dab964f853b38464033b1be15ede2839eca751482357c45abdd05a"
download \
  "https://github.com/yannh/kubeconform/releases/download/v0.8.0/kubeconform-linux-amd64.tar.gz" \
  "$download_directory/kubeconform.tar.gz" \
  "9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883"
download \
  "https://github.com/anchore/syft/releases/download/v1.51.1/syft_1.51.1_linux_amd64.tar.gz" \
  "$download_directory/syft.tar.gz" \
  "8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3"
download \
  "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz" \
  "$download_directory/trivy.tar.gz" \
  "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"
download \
  "https://github.com/cli/cli/releases/download/v2.95.0/gh_2.95.0_linux_amd64.tar.gz" \
  "$download_directory/gh.tar.gz" \
  "25d1e4729e8808c9ed3d613e96ebd3f3e44446f2d368c89d878a71a36ddb3d8c"

install -m 0755 "$download_directory/kind" "$install_directory/kind"
install -m 0755 "$download_directory/kubectl" "$install_directory/kubectl"

for executable in kubeconform syft trivy; do
  extraction_directory="$download_directory/$executable-extracted"
  mkdir "$extraction_directory"
  tar \
    --extract \
    --file "$download_directory/$executable.tar.gz" \
    --gzip \
    --directory "$extraction_directory" \
    "$executable"
  install -m 0755 "$extraction_directory/$executable" "$install_directory/$executable"
done

mkdir "$download_directory/gh-extracted"
tar \
  --extract \
  --file "$download_directory/gh.tar.gz" \
  --gzip \
  --directory "$download_directory/gh-extracted" \
  "gh_2.95.0_linux_amd64/bin/gh"
install \
  -m 0755 \
  "$download_directory/gh-extracted/gh_2.95.0_linux_amd64/bin/gh" \
  "$install_directory/gh"

"$install_directory/gh" version
"$install_directory/kind" version
"$install_directory/kubectl" version --client
"$install_directory/kubeconform" -v
"$install_directory/syft" version
"$install_directory/trivy" version
