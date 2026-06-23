# Signing and releasing the cookiesync key helper

`cookiesync-keyhelper.app` is the Developer-ID-signed, notarized, stapled bundle
that guards the browser Safe Storage password behind Touch ID and wraps the
daemon key cache against a per-boot Secure Enclave key. An ad-hoc binary is
SIGKILLed at exec on macOS 15/26 and is refused Secure Enclave keygen; only a
signed `.app` with an embedded provisioning profile and a `keychain-access-groups`
entitlement clears the AMFI kill. CI builds, signs, notarizes, and staples the
bundle, attaches it to a GitHub release, and publishes a Homebrew cask to the
shared central tap `yasyf/homebrew-tap`. `cookiesync install` shells out to
`brew install yasyf/tap/cookiesync-keyhelper`, so the same tap serves both the CLI
flow and a manual `brew install`.

The helper ships on the same `v*` tag that releases the package; the
sign/notarize/cask-publish runs only when `helper/` changed since the previous tag
(the `detect-helper-changes` job gates the costly macOS build). The pipeline lives in
the unified
[`.github/workflows/release-pypi.yml`](.github/workflows/release-pypi.yml):
the `helper-build` job imports the Developer ID cert into a throwaway keychain, derives the
signing identity and Team ID from the cert (never hardcoded), embeds the provisioning
profile, signs the inner binary and the bundle with a hardened runtime, notarizes
the bundle and fails loud unless the result is `Accepted`, staples the ticket, and
uploads the stapled `.app` (zipped) as a release asset. The `publish-cask` job then
renders `Casks/cookiesync-keyhelper.rb` — an `app` cask pointing at that release
asset, with its `sha256` — and pushes it to `yasyf/homebrew-tap` through the shared
`yasyf/homebrew-tap/.github/actions/publish` composite action. The cask uses an `app`
stanza (not a bare `binary` symlink) because the embedded provisioning profile that
authorizes the Secure Enclave is bundle-relative, so the whole `.app` must stay
intact; it carries no `--no-quarantine` hook because the bundle is notarized and
stapled.

## Facts

| Thing | Value |
| --- | --- |
| Bundle ID | `com.yasyf.cookiesync.helper` |
| Team ID | `SXKCTF23Q2` (derived from the cert at CI time, never hardcoded) |
| Keychain access group | `<TEAM_ID>.com.yasyf.cookiesync.helper` |
| Provisioning profile | "cookiesync helper Developer ID" (keychain-access-groups `SXKCTF23Q2.*`, OSX) |
| Homebrew cask | `yasyf/tap/cookiesync-keyhelper` in the shared central tap `yasyf/homebrew-tap` (not in this repo) |
| Release trigger | the same `v*` tag that releases the package; the helper sign/notarize/cask-publish runs only when `helper/` changed since the previous tag |
| Runner | `macos-15` (build); `ubuntu-latest` (cask publish) |

## Required secrets

These live in the `OpenClaw` 1Password vault and are pushed to the GitHub repo by
`set-release-secrets.sh` (see deploy step 2). The workflow reads them by these
exact names:

| Secret | What it is |
| --- | --- |
| `MACOS_SIGN_P12` | base64 Developer ID Application `.p12` (full chain — intermediate + Apple Root CA) |
| `MACOS_SIGN_PASSWORD` | password for that `.p12` |
| `MACOS_NOTARY_ISSUER_ID` | App Store Connect API issuer id (passed to `notarytool` as `--issuer`) |
| `MACOS_NOTARY_KEY_ID` | App Store Connect API key id (`--key-id`) |
| `MACOS_NOTARY_KEY` | base64 App Store Connect API `.p8` key |
| `MACOS_PROVISION_PROFILE_COOKIESYNC` | base64 "cookiesync helper Developer ID" provisioning profile |
| `HOMEBREW_TAP_TOKEN` | PAT (or fine-grained token) with `contents:write` on `yasyf/homebrew-tap`; the `publish-cask` job pushes the cask there (the default `GITHUB_TOKEN` can't push cross-repo) |

## Deploy steps (one-time, then per release)

1. **Store the provisioning profile in 1Password.** The Developer ID cert and App
   Store Connect API key already live in `OpenClaw`; the only new artifact is the
   provisioning profile. Run:

   ```bash
   bash /tmp/store-cookiesync-signing.sh
   ```

   This writes `op://OpenClaw/MACOS_PROVISION_PROFILE_COOKIESYNC/credential` (base64
   of the profile).

2. **Push the secrets to the repo.** Run repo-bootstrap's `set-release-secrets.sh`
   against `yasyf/cookiesync`:

   ```bash
   bash "${CLAUDE_PLUGIN_ROOT}/skills/repo-bootstrap/scripts/set-release-secrets.sh" yasyf/cookiesync
   ```

   The script's secret list must include `MACOS_PROVISION_PROFILE_COOKIESYNC`
   alongside the six it already pushes (`MACOS_SIGN_P12`, `MACOS_SIGN_PASSWORD`,
   `MACOS_NOTARY_ISSUER_ID`, `MACOS_NOTARY_KEY_ID`, `MACOS_NOTARY_KEY`,
   `HOMEBREW_TAP_TOKEN`) — add it to the `SECRETS` variable in that script so the
   profile lands as a repo secret.

3. **Push a `v*` tag to release the package and (if `helper/` changed) the helper.**
   For example:

   ```bash
   git tag v1.0.0 origin/main && git push origin v1.0.0
   ```

   The unified release runs from this one tag. The `detect-helper-changes` job
   diffs `helper/` against the previous `v*` tag; only when it changed (or on the
   first release, which has no prior tag) does the `helper-build` job run on a
   `macos-15` runner to sign, notarize, and staple the bundle.

4. **CI releases the asset and publishes the cask.** When the run is green and
   `helper/` changed: the GitHub release for the tag carries
   `cookiesync-keyhelper-v1.0.0-darwin.zip` (the stapled bundle) and its `.sha256`,
   and the `publish-cask` job pushes `Casks/cookiesync-keyhelper.rb` to the shared
   central tap `yasyf/homebrew-tap` (not in this repo). A hyphenated prerelease tag
   (e.g. `v1.0.0-rc1`) ships the release asset but skips the cask publish, so a
   prerelease never becomes the tap's latest.

5. **Users install from the tap.** `cookiesync install` shells out to
   `brew install yasyf/tap/cookiesync-keyhelper`, or install it by hand with the
   same command. brew downloads the asset, verifies its checksum, and lays the
   stapled `.app` into the cask appdir (`/Applications`, or `~/Applications`
   without admin rights). The notarized + stapled bundle clears Gatekeeper with no
   `--no-quarantine` hook; cookiesync then re-asserts the Developer-ID anchor before
   trusting it.

## Validating the Secure Enclave

CI cannot prove the Secure Enclave path: GitHub macOS runners have no usable
Secure Enclave, so the workflow only verifies the signature, notarization, and
staple. SE keygen (`cache-newkey`) and biometric vault retrieval can only be
exercised on a real Mac after the signed helper is installed. The bundle is
correct when, on that Mac:

- `codesign --verify --strict cookiesync-keyhelper.app` exits 0 and the binary
  runs without a SIGKILL.
- `codesign -d -r- cookiesync-keyhelper.app` shows a Developer ID anchor
  (`certificate 1[field.1.2.840.113635.100.6.2.6]`), never a bare `root`.
- `spctl -a -t install -vv cookiesync-keyhelper.app` reports
  `accepted … source=Notarized Developer ID`.
- `cookiesync-keyhelper.app/Contents/MacOS/cookiesync-keyhelper cache-newkey test`
  exits 0 (Secure Enclave keygen succeeds under the Developer ID signature).
