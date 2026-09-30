//go:build darwin

package helper

import (
	"context"

	"github.com/yasyf/synckit/authkit"
)

// VaultItem is one entry in a VaultBatchRetrieve request: the vault service the
// biometry-bound secret lives under, and the login-keychain Safe Storage service
// the helper enrolls from when the vault item is missing.
type VaultItem struct {
	Vault              string
	SafeStorageService string
}

// Bridge invokes the signed authkit helper for cookiesync's vault and per-boot
// cache subcommands. The zero value resolves the installed helper via
// authkit.RequireHelper on each call (failing closed if absent); set Binary to
// pin a path for tests.
type Bridge struct {
	// Binary, when set, is the helper executable to run; otherwise the bridge
	// resolves the installed signed helper via authkit.RequireHelper.
	Binary string
}

// run forwards one helper subcommand to the authkit exec core, which resolves
// the helper (failing closed with an *authkit.HelperError when absent), feeds
// stdin, appends extraEnv, and reports a non-zero exit in Result.Code rather
// than as an error.
func (b Bridge) run(ctx context.Context, stdin []byte, extraEnv []string, args ...string) (Result, error) {
	return authkit.Bridge{Binary: b.Binary}.Run(ctx, stdin, extraEnv, args...)
}

// VaultStatus runs the read-only vault-status probe. It never triggers a Touch ID
// prompt: it reports whether the device has a passcode/biometry and whether the
// named vault item exists, via the contract line on stdout
// (biometry=<bool> passcode=<bool> vault=<bool>) and exit 0 (present) / 2 (absent).
func (b Bridge) VaultStatus(ctx context.Context, vault string) (Result, error) {
	return b.run(ctx, nil, nil, "vault-status", vault)
}

// VaultBatchRetrieve prompts for Touch ID once and retrieves every item's vault
// secret under that single authentication, enrolling a missing vault item from
// its Safe Storage service without a second prompt. reason is set as
// AUTHKIT_REASON so the prompt text is always cookiesync's composed sentence.
// Exit 0 means the sheet was approved and the per-item outcomes are the stdout
// lines ParseBatchLines decodes; 1 is cancelled/denied, 2 is no
// biometry/passcode, CodePresenceUnavailable is a locked keybag which aborts
// the whole batch, and CodeCallerRejected is a rejected caller or usage error
// that fails hard.
func (b Bridge) VaultBatchRetrieve(ctx context.Context, items []VaultItem, reason string) (Result, error) {
	args := make([]string, 0, 1+2*len(items))
	args = append(args, "vault-batch-retrieve")
	for _, item := range items {
		args = append(args, item.Vault, item.SafeStorageService)
	}
	return b.run(ctx, nil, []string{authkit.ReasonEnvVar + "=" + reason}, args...)
}

// CacheNewkey generates the per-boot ephemeral Secure-Enclave P-256 key under
// label, dropping any stale cache keys first. Exit 0 is success; 2 means no
// Enclave or keygen misconfigured; CodePresenceUnavailable means the keybag is
// locked (no user present).
func (b Bridge) CacheNewkey(ctx context.Context, label string) (Result, error) {
	return b.run(ctx, nil, nil, "cache-newkey", label)
}

// CacheWrap ECIES-encrypts plaintext against the Enclave public key for label and
// returns the opaque blob on stdout. Exit 0 is success; 1 means the key is missing
// or the encrypt failed; CodePresenceUnavailable means the keybag is locked.
// plaintext and the returned blob are raw bytes.
func (b Bridge) CacheWrap(ctx context.Context, label string, plaintext []byte) (Result, error) {
	return b.run(ctx, plaintext, nil, "cache-wrap", label)
}

// CacheUnwrap ECIES-decrypts blob with the Enclave private key for label and
// returns the plaintext on stdout. Exit 0 is success; 1 means the key is missing
// or the decrypt failed; CodePresenceUnavailable means the keybag is locked.
// blob and the returned plaintext are raw bytes.
func (b Bridge) CacheUnwrap(ctx context.Context, label string, blob []byte) (Result, error) {
	return b.run(ctx, blob, nil, "cache-unwrap", label)
}

// CacheDropkey deletes the Enclave key under label. It exits 0 even when the key
// is already gone, so cleanup is idempotent.
func (b Bridge) CacheDropkey(ctx context.Context, label string) (Result, error) {
	return b.run(ctx, nil, nil, "cache-dropkey", label)
}

// CDPUnlock runs vault-retrieve-biometric: the strict biometrics-only vault read
// for the live CDP bridge, with no passcode fallback. reason is set as
// AUTHKIT_REASON. stdout is the raw Safe Storage password. Exit 0 is success, 1
// cancelled/denied, 2 vault missing, and CodePresenceUnavailable is biometrics
// unavailable or a locked keybag.
func (b Bridge) CDPUnlock(ctx context.Context, vault, reason string) (Result, error) {
	return b.run(ctx, nil, []string{authkit.ReasonEnvVar + "=" + reason}, "vault-retrieve-biometric", vault)
}
