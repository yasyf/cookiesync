// Package helper bridges cookiesync to the installed, Developer-ID-signed
// Secure-Enclave key helper (cookiesync-keyhelper.app). It shells the helper's
// subcommands: the read-only vault probe (vault-status), the biometric vault
// (vault-retrieve / vault-batch-retrieve / vault-enroll), and the per-boot
// Enclave key cache (cache-newkey / cache-wrap / cache-unwrap / cache-dropkey).
//
// The bridge fails closed: a missing helper surfaces a *paths.HelperError rather
// than degrading to an unsigned fallback, since an ad-hoc helper is SIGKILLed at
// exec by AMFI and refused the Enclave. Each call returns the helper's raw exit
// code, stdout, and stderr so callers branch on the documented 0 (success) / 1
// (failed/denied/cancelled, do not retry) / 2 (unavailable/not-found, may be
// recoverable) / 3 (Enclave presence unavailable: keybag locked, retry after
// unlock) contract and log the helper's stderr diagnostics.
package helper

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/yasyf/cookiesync/internal/paths"
)

// reasonEnvVar is the environment variable vault-retrieve reads for the Touch ID
// prompt text. cookiesync always sets it to a composed, host-specific reason so
// the helper never falls back to its generic "unlock your cookie vault" default.
const reasonEnvVar = "COOKIESYNC_TOUCHID_REASON"

// CodePresenceUnavailable is the helper exit code for a Secure-Enclave call the
// data-protection keybag refused with errSecInteractionNotAllowed (-25308): the
// screen is locked or no user is present. Distinct from 2 (no Enclave hardware or
// a genuine misconfiguration) so callers can degrade instead of failing.
const CodePresenceUnavailable = 3

// unknownSubcommandStderr is the exact stderr a helper that predates
// vault-batch-retrieve (<= v0.7.0) writes when handed the verb, paired with exit
// code 2. IsUnknownSubcommand sniffs it to tell a stale installed helper apart
// from a genuine unavailable failure, which shares the exit code.
const unknownSubcommandStderr = "keyhelper: unknown subcommand 'vault-batch-retrieve'\n"

// BatchStatus is the status column of one vault-batch-retrieve stdout line.
type BatchStatus string

// The three per-item outcomes of a vault-batch-retrieve line.
const (
	BatchOK      BatchStatus = "ok"
	BatchMissing BatchStatus = "missing"
	BatchError   BatchStatus = "error"
)

// Result is the outcome of one helper subcommand: the raw exit code and the bytes
// the helper wrote to stdout and stderr. On a non-zero exit, Stderr carries the
// helper's diagnostic line (the failing operation and its numeric OSStatus) so
// callers can log and classify the failure.
type Result struct {
	Code   int
	Stdout []byte
	Stderr []byte
}

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

// Bridge invokes the signed key helper. The zero value resolves the installed
// helper via paths.RequireHelper on each call (failing closed if absent); set
// Binary to pin a path for tests.
type Bridge struct {
	// Binary, when set, is the helper executable to run; otherwise the bridge
	// resolves the installed signed helper via paths.RequireHelper.
	Binary string
}

// binary resolves the helper executable, failing closed with a *paths.HelperError
// when none is installed.
func (b Bridge) binary() (string, error) {
	if b.Binary != "" {
		return b.Binary, nil
	}
	return paths.RequireHelper()
}

// VaultStatus runs the read-only vault-status probe. It never triggers a Touch ID
// prompt: it reports whether the device has a passcode/biometry and whether the
// named vault item exists, via the contract line on stdout
// (biometry=<bool> passcode=<bool> vault=<bool>) and exit 0 (present) / 2 (absent).
func (b Bridge) VaultStatus(ctx context.Context, vault string) (Result, error) {
	return b.run(ctx, nil, nil, "vault-status", vault)
}

// VaultRetrieve prompts for Touch ID (or device passcode) and returns the stored
// Safe Storage password on stdout. reason is set as COOKIESYNC_TOUCHID_REASON so
// the prompt text is always cookiesync's composed, host-specific sentence. Exit 0
// is success, 1 is cancelled/denied, 2 is an invalidated ACL or no biometry.
func (b Bridge) VaultRetrieve(ctx context.Context, vault, reason string) (Result, error) {
	return b.run(ctx, nil, []string{reasonEnvVar + "=" + reason}, "vault-retrieve", vault)
}

// VaultBatchRetrieve prompts for Touch ID once and retrieves every item's vault
// secret under that single authentication, enrolling a missing vault item from
// its Safe Storage service without a second prompt. Exit 0 means the sheet was
// approved and the per-item outcomes are the stdout lines ParseBatchLines
// decodes; 1 is cancelled/denied, 2 is no biometry/passcode — or a stale
// pre-batch helper, see IsUnknownSubcommand — and CodePresenceUnavailable is a
// locked keybag, which aborts the whole batch.
func (b Bridge) VaultBatchRetrieve(ctx context.Context, items []VaultItem, reason string) (Result, error) {
	args := make([]string, 0, 1+2*len(items))
	args = append(args, "vault-batch-retrieve")
	for _, item := range items {
		args = append(args, item.Vault, item.SafeStorageService)
	}
	return b.run(ctx, nil, []string{reasonEnvVar + "=" + reason}, args...)
}

// VaultEnroll stores the Safe Storage password (read from safeStorageService in
// the login keychain) into a biometry-or-passcode-bound vault item. Exit 0 is
// success; 1 (add failed) and 2 (could not read source) are failures.
func (b Bridge) VaultEnroll(ctx context.Context, vault, safeStorageService string) (Result, error) {
	return b.run(ctx, nil, nil, "vault-enroll", vault, safeStorageService)
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

// run executes one helper subcommand, feeding stdin (when non-nil) and appending
// extraEnv to the inherited environment. It returns the helper's exit code,
// stdout, and stderr; a non-zero exit is reported in Result.Code, not as an
// error, so callers branch on the 0/1/2/3 contract. err is non-nil only when the
// helper cannot be resolved or spawned, or it dies on a signal.
func (b Bridge) run(ctx context.Context, stdin []byte, extraEnv []string, args ...string) (Result, error) {
	bin, err := b.binary()
	if err != nil {
		return Result{}, err
	}
	//nolint:gosec // G204: bin is the tool's own resolved signed helper and args are fixed subcommands, not user-supplied.
	cmd := exec.CommandContext(ctx, bin, args...)
	if extraEnv != nil {
		cmd.Env = append(cmd.Environ(), extraEnv...)
	}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	switch runErr := cmd.Run(); {
	case runErr == nil:
		return Result{Code: 0, Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, nil
	case isExit(runErr):
		var exitErr *exec.ExitError
		errors.As(runErr, &exitErr)
		return Result{Code: exitErr.ExitCode(), Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, nil
	default:
		return Result{}, fmt.Errorf("run %s %v: %w: %s", bin, args, runErr, bytes.TrimSpace(stderr.Bytes()))
	}
}

// isExit reports whether err is a clean non-zero process exit (ExitCode >= 0). A
// signal kill reports ExitCode() == -1, which is a genuine run failure, not a
// contract exit code, so it is excluded.
func isExit(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() >= 0
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

// IsUnknownSubcommand reports whether res is a stale installed helper (one that
// predates vault-batch-retrieve) rejecting the verb: exit code 2 with exactly the
// unknown-subcommand diagnostic on stderr. Callers use it to fall back to
// per-item vault-retrieve instead of treating the exit as a real failure.
func IsUnknownSubcommand(res Result) bool {
	return res.Code == 2 && string(res.Stderr) == unknownSubcommandStderr
}
