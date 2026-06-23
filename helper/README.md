# cookiesync-keyhelper

One Developer-ID-signable `.app` that does the two security-critical jobs cookiesync needs on macOS: it guards a browser's Safe Storage password behind a real Touch ID (or passcode) prompt, and it wraps the daemon's short-lived key cache against a per-boot Secure Enclave key. Both jobs used to be separate Swift sources compiled and ad-hoc signed at runtime; they now live in one binary so a single Developer ID signature + provisioning profile can authorize the Secure Enclave.

## Why a signed `.app`, not an ad-hoc binary

macOS 15 and 26 SIGKILL a Team-less (ad-hoc) signature the moment it execs, and Secure Enclave key generation is refused outright under an ad-hoc signature. The fix that gets past the AMFI kill (exit 137 becomes `errSecSuccess`/`-34018` clears): a **Developer ID Application** signature, a hardened runtime, an embedded provisioning profile, and a `keychain-access-groups` entitlement. The provisioning profile authorizes the keychain group the SE keys and vault items live in.

So this bundle is only useful once it is **signed, notarized, stapled, and carries an embedded provisioning profile.** The unsigned bundle that `build-app.sh` produces assembles the same layout for local dev, but it cannot touch the Secure Enclave — `build-app.sh` exists to verify the bundle structure, not to run it.

## Bundle layout

```
cookiesync-keyhelper.app/
└── Contents/
    ├── Info.plist                 # CFBundleIdentifier com.yasyf.cookiesync.helper
    ├── MacOS/
    │   └── cookiesync-keyhelper   # the compiled CLI
    └── embedded.provisionprofile  # the Developer ID provisioning profile (CI adds this)
```

- **Bundle ID:** `com.yasyf.cookiesync.helper`
- **Keychain access group:** `<TEAM_ID>.com.yasyf.cookiesync.helper` — every keychain item the helper writes (the biometry-bound vault password and the per-boot SE cache key) is scoped to this group, so the provisioning-profile entitlement authorizes them.
- **Entitlements** (`cookiesync-keyhelper.entitlements`, with `$(TEAM_ID)` substituted at build time): `keychain-access-groups` and `com.apple.application-identifier`, both `<TEAM_ID>.com.yasyf.cookiesync.helper`.

## Subcommand contract

The CLI dispatches on `argv[1]`. Two families share one binary.

### Consent vault — biometry-or-passcode-bound Safe Storage password

| Command | Arguments | I/O | Exit |
| --- | --- | --- | --- |
| `vault-enroll` | `<vault-service> <safe-storage-service>` | reads the Safe Storage password from the login keychain, re-stores it under a `.biometryCurrentSet .or .devicePasscode` access control | `0` ok / `1` add failed / `2` could not read the source password |
| `vault-retrieve` | `<vault-service>` | forces a Touch ID / passcode evaluation, then writes the password to stdout | `0` ok / `1` cancelled or denied / `2` unavailable, not found, or ACL invalidated (re-enroll) |
| `vault-status` | `<vault-service>` | writes `biometry=<bool> passcode=<bool> vault=<bool>` to stdout | `0` vault present and usable / `2` no passcode or vault absent |

`vault-retrieve` reads its prompt text from the `COOKIESYNC_TOUCHID_REASON` environment variable, falling back to `unlock your cookie vault`.

### Secure Enclave cache — per-boot ephemeral P-256 ECIES wrapper

| Command | Arguments | I/O | Exit |
| --- | --- | --- | --- |
| `cache-newkey` | `<label>` | deletes every stale cache key, then creates the per-boot SE key | `0` ok / `2` no Secure Enclave or keygen refused |
| `cache-wrap` | `<label>` | stdin plaintext → stdout ECIES blob (cofactor X9.63 SHA-256 AES-GCM) | `0` ok / `1` key missing or encrypt failed |
| `cache-unwrap` | `<label>` | stdin blob → stdout plaintext | `0` ok / `1` key missing or decrypt failed |
| `cache-dropkey` | `<label>` | deletes the SE key for `<label>` | `0` always |

The SE private key never leaves the Enclave; only the live per-boot key can unwrap a blob, so a leaked cache file or a core dump is useless off-box.

### Exit codes (both families)

- `0` — success
- `1` — cancelled, denied, or operation failed (key missing, decrypt failed, bad input)
- `2` — unavailable (no biometrics and no passcode, no Secure Enclave, item not found, non-interactive, keygen refused)

## Building locally

```bash
bash helper/build-app.sh <TEAM_ID> [provisioning-profile-path]
```

Compiles `main.swift` into `Contents/MacOS/cookiesync-keyhelper`, copies `Info.plist`, writes `build/cookiesync-keyhelper.entitlements` with `<TEAM_ID>` filled in, and — when you pass a profile path — copies it to `Contents/embedded.provisionprofile`. It prints the `.app` path and signs nothing. Signing, notarization, and stapling happen in the CI release workflow, which imports the Developer ID certificate into a throwaway keychain and runs `codesign --options runtime --timestamp --entitlements build/cookiesync-keyhelper.entitlements` followed by `xcrun notarytool submit --wait` and `xcrun stapler staple`.
