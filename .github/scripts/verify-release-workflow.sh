#!/usr/bin/env bash
set -euo pipefail

workflow=.github/workflows/release.yml
expected="$RUNNER_TEMP/cookiesync-release-action-refs"
actual="$RUNNER_TEMP/cookiesync-release-action-refs-actual"

cat > "$expected" <<'REFS'
yasyf/homebrew-tap/.github/actions/import-developer-id@19c3d5013032ad9c88f9a8f1170d1f366c19b8d9
yasyf/homebrew-tap/.github/actions/publish-draft-release@54e3e194bda69896894a82c17fcdb2822beefab5
yasyf/homebrew-tap/.github/actions/publish-draft-release@c70d7e51bdb512db2a73d054e3a94afe0a61eedb
yasyf/homebrew-tap/.github/actions/publish@9ca67392d45d66b6ae01e262383c8f3138d56f5e
yasyf/homebrew-tap/.github/actions/render-formula@19c3d5013032ad9c88f9a8f1170d1f366c19b8d9
yasyf/homebrew-tap/.github/actions/stage-draft-release@e4c3108e693681df1a3c666bae80e890bc44cf3e
yasyf/homebrew-tap/.github/actions/tap-delivery@c70d7e51bdb512db2a73d054e3a94afe0a61eedb
yasyf/homebrew-tap/.github/actions/tap-delivery@c70d7e51bdb512db2a73d054e3a94afe0a61eedb
yasyf/homebrew-tap/.github/actions/verify-tag-on-main@19c3d5013032ad9c88f9a8f1170d1f366c19b8d9
yasyf/homebrew-tap/.github/actions/wrap-daemon-bundle@19c3d5013032ad9c88f9a8f1170d1f366c19b8d9
REFS
grep -Eo 'yasyf/homebrew-tap/[^[:space:]]+@[0-9a-f]{40}' "$workflow" | sort > "$actual"
diff -u "$expected" "$actual"

if grep -Eq 'release-go.yml|softprops/action-gh-release|attach-to-release' "$workflow"; then
  echo "release helpers must not publish before the caller verifies every asset" >&2
  exit 1
fi
if grep -Eq '/releases/tags/|gh release (create|upload|download|edit|view)|uploads\.github\.com|goreleaser release .*--draft|assets\?name=|releases\?per_page=|releases/assets/' "$workflow"; then
  echo "release staging must remain draft-only and release-ID-addressed" >&2
  exit 1
fi

for required in \
  'name: Verify source' \
  'goreleaser release --clean --skip=publish' \
  'name: Package and smoke-test CookieSync.app' \
  'name: Record the exact release asset manifest' \
  'name: Stage and verify the complete draft release' \
  'stage-draft-release@e4c3108e693681df1a3c666bae80e890bc44cf3e' \
  'name: Verify signatures and checksums from the exact staged release' \
  "steps.stage.outputs['download-dir']" \
  'shasum -a 256 -c checksums.txt' \
  'name: Package immutable release and Homebrew delivery' \
  'tap-delivery@c70d7e51bdb512db2a73d054e3a94afe0a61eedb' \
  'name: Upload immutable release and Homebrew delivery' \
  'actions/upload-artifact@v7' \
  'name: Publish the verified release' \
  'publish-draft-release@54e3e194bda69896894a82c17fcdb2822beefab5' \
  "release-id: \${{ steps.stage.outputs['release-id'] }}" \
  'manifest: ${{ steps.manifest.outputs.path }}' \
  'name: Download immutable release and Homebrew delivery' \
  'actions/download-artifact@v8' \
  'name: Verify immutable release and Homebrew delivery' \
  'name: Reverify the published release by exact ID' \
  'require-published: "true"' \
  'name: Publish the preserved cask to the tap'; do
  grep -Fq -- "$required" "$workflow"
done

line() { grep -Fn "$1" "$workflow" | cut -d: -f1; }
verify="$(line 'name: Verify source')"
draft="$(line 'name: Build, sign, and notarize CLI assets without publishing')"
app="$(line 'name: Package and smoke-test CookieSync.app')"
manifest="$(line 'name: Record the exact release asset manifest')"
stage="$(line 'name: Stage and verify the complete draft release')"
verify_staged="$(line 'name: Verify signatures and checksums from the exact staged release')"
bundle="$(line 'name: Package immutable release and Homebrew delivery')"
upload="$(line 'name: Upload immutable release and Homebrew delivery')"
publish="$(line 'name: Publish the verified release')"
download="$(line 'name: Download immutable release and Homebrew delivery')"
verify_delivery="$(line 'name: Verify immutable release and Homebrew delivery')"
reverify="$(line 'name: Reverify the published release by exact ID')"
cask="$(line 'name: Publish the preserved cask to the tap')"
test "$verify" -lt "$draft"
test "$draft" -lt "$app"
test "$app" -lt "$manifest"
test "$manifest" -lt "$stage"
test "$stage" -lt "$verify_staged"
test "$verify_staged" -lt "$bundle"
test "$bundle" -lt "$upload"
test "$upload" -lt "$publish"
test "$publish" -lt "$download"
test "$download" -lt "$verify_delivery"
test "$verify_delivery" -lt "$reverify"
test "$reverify" -lt "$cask"

release_block="$RUNNER_TEMP/cookiesync-release-job"
tap_block="$RUNNER_TEMP/cookiesync-publish-tap-job"
awk '/^  release:/{copy=1} /^  publish-tap:/{copy=0} copy' "$workflow" > "$release_block"
awk '/^  publish-tap:/{copy=1} copy' "$workflow" > "$tap_block"

if grep -Fq 'HOMEBREW_TAP_TOKEN' "$release_block"; then
  echo "the release job must not own tap publication credentials" >&2
  exit 1
fi
if grep -Fq 'github/actions/publish@' "$release_block"; then
  echo "the release job must not publish the tap" >&2
  exit 1
fi
if grep -Eq 'Import Developer ID|goreleaser release|stage-draft-release@|wrap-daemon-bundle@' "$tap_block"; then
  echo "the tap retry job must not rebuild, sign, notarize, or stage release assets" >&2
  exit 1
fi
