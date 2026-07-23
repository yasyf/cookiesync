#!/usr/bin/env bash
set -euo pipefail

workflow=.github/workflows/release.yml
pin=19c3d5013032ad9c88f9a8f1170d1f366c19b8d9

test "$(grep -Ec 'uses: yasyf/homebrew-tap/.+@' "$workflow")" = 5
test "$(grep -Ec "uses: yasyf/homebrew-tap/.+@${pin}$" "$workflow")" = 5
if grep -Eq 'release-go.yml|softprops/action-gh-release|attach-to-release' "$workflow"; then
  echo "release helpers must not publish before the caller verifies every asset" >&2
  exit 1
fi
if grep -Eq '/releases/tags/|gh release (upload|download|edit|view)|--hostname uploads.github.com|goreleaser release .*--draft|assets\?name=' "$workflow"; then
  echo "release staging must remain draft-only and release-ID-addressed" >&2
  exit 1
fi

for required in \
  'name: Verify source' \
  'goreleaser release --clean --skip=publish' \
  'name: Package and smoke-test CookieSync.app' \
  'name: Stage and verify the complete draft release' \
  'gh api --paginate --slurp' \
  'releases?per_page=100' \
  'assets?per_page=100' \
  'https://uploads.github.com/repos/' \
  '-f "name=' \
  'steps.stage.outputs.release-id' \
  'gh api --method PATCH' \
  'shasum -a 256 -c checksums.txt' \
  'name: Publish the verified release' \
  'name: Publish the cask to the tap'; do
  grep -Fq -- "$required" "$workflow"
done

line() { grep -Fn "$1" "$workflow" | cut -d: -f1; }
verify="$(line 'name: Verify source')"
draft="$(line 'name: Build, sign, and notarize CLI assets without publishing')"
app="$(line 'name: Package and smoke-test CookieSync.app')"
stage="$(line 'name: Stage and verify the complete draft release')"
publish="$(line 'name: Publish the verified release')"
cask="$(line 'name: Publish the cask to the tap')"
test "$verify" -lt "$draft"
test "$draft" -lt "$app"
test "$app" -lt "$stage"
test "$stage" -lt "$publish"
test "$publish" -lt "$cask"
