# Signing and releasing the cookiesync key helper

`cookiesync-keyhelper.app` is the Developer-ID-signed, notarized, stapled bundle
that guards the browser Safe Storage password behind Touch ID and wraps the
daemon key cache against a per-boot Secure Enclave key. An ad-hoc binary is
SIGKILLed at exec on macOS 15/26 and is refused Secure Enclave keygen; only a
signed `.app` with an embedded provisioning profile and a `keychain-access-groups`
entitlement clears the AMFI kill. CI builds, signs, notarizes, staples, and
attaches the bundle to a GitHub release so `cookiesync install` can download it.

The pipeline lives in
[`.github/workflows/helper-release.yml`](.github/workflows/helper-release.yml):
it imports the Developer ID cert into a throwaway keychain, derives the signing
identity and Team ID from the cert (never hardcoded), embeds the provisioning
profile, signs the inner binary and the bundle with a hardened runtime, notarizes
the bundle and fails loud unless the result is `Accepted`, staples the ticket,
and uploads the stapled `.app` (zipped) as a release asset.

## Facts

| Thing | Value |
| --- | --- |
| Bundle ID | `com.yasyf.cookiesync.helper` |
| Team ID | `SXKCTF23Q2` (derived from the cert at CI time, never hardcoded) |
| Keychain access group | `<TEAM_ID>.com.yasyf.cookiesync.helper` |
| Provisioning profile | "cookiesync helper Developer ID" (keychain-access-groups `SXKCTF23Q2.*`, OSX) |
| Release trigger | a `helper-v*` tag (or a manual `workflow_dispatch` run, which builds + signs but cuts no release) |
| Runner | `macos-15` |

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
| `HOMEBREW_TAP_TOKEN` | (unused by this workflow; the release asset is the primary distribution) |

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

3. **Push a `helper-v*` tag to trigger the workflow.** For example:

   ```bash
   git tag helper-v1.0.0 && git push origin helper-v1.0.0
   ```

   The signing pipeline runs on a `macos-15` runner.

4. **The signed `.app` lands as a release asset.** When the run is green, the
   GitHub release for the tag carries
   `cookiesync-keyhelper-v1.0.0-darwin.zip` (the stapled bundle) and its
   `.sha256`. `cookiesync install` downloads and unzips it on the user's Mac.

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
