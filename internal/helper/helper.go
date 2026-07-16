// Package helper bridges cookiesync to the installed, Developer-ID-signed
// authkit helper app. It shells the helper's cookiesync subcommands over the
// generic authkit.Bridge exec core: the read-only vault probe (vault-status),
// the biometric vault (vault-batch-retrieve / vault-retrieve-biometric), and
// the per-boot Enclave key cache (cache-newkey / cache-wrap / cache-unwrap /
// cache-dropkey).
//
// The bridge fails closed: a missing helper surfaces an *authkit.HelperError
// rather than degrading to an unsigned fallback, since an ad-hoc helper is
// SIGKILLed at exec by AMFI and refused the Enclave. Each call returns the
// helper's raw exit code, stdout, and stderr so callers branch on the
// documented 0 (success) / 1 (failed/denied/cancelled) / 2
// (unavailable/not-found) / CodePresenceUnavailable (keybag locked, retry after
// unlock) contract and log the helper's stderr diagnostics.
package helper

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/yasyf/synckit/authkit"
)

// CodePresenceUnavailable is the helper exit code for a Secure-Enclave call the
// data-protection keybag refused with errSecInteractionNotAllowed (-25308): the
// screen is locked or no user is present. It is authkit's screen-locked code,
// kept under cookiesync's name so callers can degrade instead of failing.
const CodePresenceUnavailable = authkit.CodeScreenLocked

// BatchStatus is the status column of one vault-batch-retrieve stdout line.
type BatchStatus string

// The three per-item outcomes of a vault-batch-retrieve line.
const (
	BatchOK      BatchStatus = "ok"
	BatchMissing BatchStatus = "missing"
	BatchError   BatchStatus = "error"
)

// Result is the outcome of one helper subcommand: the raw exit code and the
// bytes the helper wrote to stdout and stderr. It aliases authkit.Result so the
// cache and consent wrappers keep their signatures over the generic exec core.
type Result = authkit.Result

// VaultItem is one entry in a VaultBatchRetrieve request: the vault service the
// biometry-bound secret lives under, and the login-keychain Safe Storage service
// the helper enrolls from when the vault item is missing.
type VaultItem struct {
	Vault              string
	SafeStorageService string
}

// BatchLine is one parsed vault-batch-retrieve stdout line. Index is the
// zero-based position of the item in the request. Payload holds the decoded
// secret for BatchOK and is nil otherwise; OSStatus holds the failing Security
// status for BatchError and is zero otherwise.
type BatchLine struct {
	Index    int
	Status   BatchStatus
	Payload  []byte
	OSStatus int32
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
// biometry/passcode, and CodePresenceUnavailable is a locked keybag, which
// aborts the whole batch.
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

// ParseBatchLines decodes vault-batch-retrieve stdout: one
// "<index>\t<status>\t<payload>" line per requested item, where payload is the
// base64 secret (ok), "-" (missing), or the failing OSStatus in decimal (error).
// Any malformed line fails the whole parse.
func ParseBatchLines(stdout string) ([]BatchLine, error) {
	trimmed := strings.TrimSuffix(stdout, "\n")
	if trimmed == "" {
		return nil, nil
	}
	raw := strings.Split(trimmed, "\n")
	lines := make([]BatchLine, len(raw))
	for i, line := range raw {
		parsed, err := parseBatchLine(line)
		if err != nil {
			return nil, fmt.Errorf("batch line %d: %w", i, err)
		}
		lines[i] = parsed
	}
	return lines, nil
}

func parseBatchLine(line string) (BatchLine, error) {
	fields := strings.Split(line, "\t")
	if len(fields) != 3 {
		return BatchLine{}, fmt.Errorf("want 3 tab-separated fields in %q, got %d", line, len(fields))
	}
	index, err := strconv.Atoi(fields[0])
	if err != nil {
		return BatchLine{}, fmt.Errorf("index %q: %w", fields[0], err)
	}
	switch status := BatchStatus(fields[1]); status {
	case BatchOK:
		payload, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil {
			return BatchLine{}, fmt.Errorf("ok payload %q: %w", fields[2], err)
		}
		return BatchLine{Index: index, Status: BatchOK, Payload: payload}, nil
	case BatchMissing:
		if fields[2] != "-" {
			return BatchLine{}, fmt.Errorf(`missing payload %q, want "-"`, fields[2])
		}
		return BatchLine{Index: index, Status: BatchMissing}, nil
	case BatchError:
		osStatus, err := strconv.ParseInt(fields[2], 10, 32)
		if err != nil {
			return BatchLine{}, fmt.Errorf("error payload %q: %w", fields[2], err)
		}
		return BatchLine{Index: index, Status: BatchError, OSStatus: int32(osStatus)}, nil
	default:
		return BatchLine{}, fmt.Errorf("unknown status %q in %q", fields[1], line)
	}
}
