#!/usr/bin/env bash
set -euo pipefail

binary="$1"
version="$2"

fail() {
  echo "::error::$binary: $1" >&2
  exit 1
}

description="$(file -b "$binary")"
case "$description" in
  "ELF 64-bit LSB executable, x86-64,"*) ;;
  *) fail "not an x86-64 ELF executable: $description" ;;
esac
case "$description" in
  *interpreter*) fail "carries a PT_INTERP program interpreter: $description" ;;
  *"statically linked"*) ;;
  *) fail "not statically linked: $description" ;;
esac

settings="$(go version -m "$binary" | awk -F'\t' '$2 == "build" { print $3 }')"
for want in \
  'CGO_ENABLED=0' \
  'GOOS=linux' \
  'GOARCH=amd64' \
  'vcs.modified=false' \
  "-ldflags=\"-s -w -X main.version=$version\""; do
  grep -Fxq -- "$want" <<< "$settings" || fail "build info lacks $want"
done
