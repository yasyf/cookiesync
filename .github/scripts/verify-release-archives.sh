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
file -b "$unpacked/cookiesync_darwin_amd64/cookiesync" | grep -Fq 'Mach-O 64-bit executable x86_64'
file -b "$unpacked/cookiesync_darwin_arm64/cookiesync" | grep -Fq 'Mach-O 64-bit executable arm64'
bash "$scripts/verify-static-elf.sh" "$unpacked/cookiesync_linux_amd64/cookiesync" "$version"
