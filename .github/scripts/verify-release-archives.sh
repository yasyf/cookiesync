#!/usr/bin/env bash
set -euo pipefail

dir="$1"
version="$2"
scripts="$(cd "$(dirname "$0")" && pwd)"
archives=(
  cookiesync_darwin_amd64.tar.gz
  cookiesync_darwin_arm64.tar.gz
  cookiesync_linux_amd64.tar.gz
)

(
  cd "$dir"
  diff -u <(printf '%s\n' "${archives[@]}") <(awk '{ print $2 }' checksums.txt | LC_ALL=C sort)
  shasum -a 256 -c checksums.txt
)

unpacked="$RUNNER_TEMP/cookiesync-release-archives"
rm -rf "$unpacked"
for archive in "${archives[@]}"; do
  target="$unpacked/${archive%.tar.gz}"
  mkdir -p "$target"
  tar -xzf "$dir/$archive" -C "$target"
  test -f "$target/cookiesync"
done
expect_macho() {
  local description
  description="$(file -b "$1")"
  if [[ "$description" != *Mach-O\ 64-bit* || "$description" != *"$2"* ]]; then
    echo "::error::$1 is not a Mach-O 64-bit $2 executable: $description" >&2
    exit 1
  fi
}
expect_macho "$unpacked/cookiesync_darwin_amd64/cookiesync" x86_64
expect_macho "$unpacked/cookiesync_darwin_arm64/cookiesync" arm64
bash "$scripts/verify-static-elf.sh" "$unpacked/cookiesync_linux_amd64/cookiesync" "$version"
