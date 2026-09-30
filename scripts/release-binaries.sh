#!/usr/bin/env bash
set -euo pipefail

version=${1:?provide the release version}
if [[ ! "$version" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || (( ${#version} > 128 )); then
  echo 'Use a version tag such as v0.5.0 or v0.5.0-rc.1.' >&2
  exit 1
fi

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
mkdir -p "${2:-dist}"
output=$(cd "${2:-dist}" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
  os=${target%/*}
  arch=${target#*/}
  directory="$work/${os}_${arch}"
  mkdir -p "$directory"
  binary=imds-credential-server
  if [[ "$os" == windows ]]; then binary+=.exe; fi
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags="-s -w -X main.Version=${version}" -o "$directory/$binary" .
  cp LICENSE NOTICE CONTRIBUTORS.md README.md "$directory/"
  archive="imds-credential-server_${version}_${os}_${arch}"
  if [[ "$os" == windows ]]; then
    (cd "$directory" && zip -q "$output/$archive.zip" ./*)
  else
    tar -czf "$output/$archive.tar.gz" -C "$directory" .
  fi
done

(cd "$output" && sha256sum ./*.tar.gz ./*.zip > SHA256SUMS)
