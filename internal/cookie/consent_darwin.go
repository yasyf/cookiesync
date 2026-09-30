//go:build darwin

package cookie

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/yasyf/cookiesync/internal/helper"
)

// securityBin is the macOS Keychain CLI used for the non-interactive Safe Storage
// read on hosts with no biometry/passcode, and for the owning-host unprompted
// release after a routed approval. It is a var so tests can point it at a fake.
var securityBin = "/usr/bin/security"

// TouchIDConsent is a Secure-Enclave-bound key vault: one biometric tap unlocks
// the cached Safe Storage key. The biometric vault and re-store run inside the
// installed, Developer-ID-signed authkit.app via the helper bridge; a missing
// helper fails closed rather than degrading to an unsigned build.
type TouchIDConsent struct {
	// Helper is the bridge to the signed key helper. The zero value resolves the
	// installed helper on each call.
	Helper helper.Bridge
}

// vaultName is the keychain service holding browser's biometry-bound Safe Storage
// password: "cookiesync.vault." + the browser's name.
func vaultName(browser Browser) string {
	return "cookiesync.vault." + string(browser.Name)
}

// ObtainKeyUnprompted releases browser's key non-interactively, via a bare
// Keychain read — no Touch ID. For the owning host only, and only after a verified
// routed approval from the active-session peer has already gated the release: the
// user-presence check must have happened over the routed-consent handshake first.
func (c TouchIDConsent) ObtainKeyUnprompted(ctx context.Context, browser Browser) (AesKey, error) {
	password, err := readSafeStorage(ctx, browser.KeychainService)
	if err != nil {
		return nil, err
	}
	return DeriveKey(password), nil
}

// ObtainKey releases browser's Safe Storage key behind one Touch ID (or passcode)
// tap: an ObtainKeys batch of one. A Missing outcome — no vault item and no Safe
// Storage password — surfaces as a ConsentError, preserving the single-path
// error shape.
func (c TouchIDConsent) ObtainKey(ctx context.Context, browser Browser, reason string) (AesKey, error) {
	outcomes, err := c.ObtainKeys(ctx, []Browser{browser}, reason)
	if err != nil {
		return nil, err
	}
	outcome := outcomes[0]
	if outcome.Err != nil {
		return nil, outcome.Err
	}
	if outcome.Missing {
		return nil, &ConsentError{Msg: fmt.Sprintf("could not read %q from the Keychain (denied or missing)", browser.KeychainService)}
	}
	return outcome.Key, nil
}

// ObtainKeyBiometric releases browser's Safe Storage key behind a strict
// biometric-only tap via the helper's vault-retrieve-biometric op — no passcode
// and no bare Keychain fallback, so an unavailable biometry or locked keybag
// fails closed rather than degrading. It is the gate the live CDP bridge uses.
func (c TouchIDConsent) ObtainKeyBiometric(ctx context.Context, browser Browser, reason string) (AesKey, error) {
	res, err := c.Helper.CDPUnlock(ctx, vaultName(browser), ComposeReason(browser.Display, reason))
	if err != nil {
		return nil, err
	}
	switch res.Code {
	case 0:
		return DeriveKey(SafeStorageKey(res.Stdout)), nil
	case 1:
		return nil, &ConsentError{Msg: "Touch ID (biometric) was cancelled or denied"}
	case helper.CodePresenceUnavailable:
		return nil, &ConsentError{Msg: "biometric authentication unavailable (no enrolled biometry, locked out, or screen locked)", Err: ErrKeybagLocked}
	case 2:
		return nil, &ConsentError{Msg: "bridge vault missing — re-enroll", Err: ErrBridgeVaultMissing}
	default:
		return nil, fmt.Errorf("vault-retrieve-biometric exited %d: %s", res.Code, bytes.TrimSpace(res.Stderr))
	}
}

// ObtainKeys releases every browser's Safe Storage key behind one Touch ID (or
// passcode) sheet via vault-batch-retrieve, which enrolls a missing vault item
// under the same authentication. A denied sheet or a locked keybag fails the
// whole batch with a ConsentError; no biometry and no passcode (exit 2) degrades
// to bare per-browser Keychain reads; a rejected caller (exit 4) never degrades.
func (c TouchIDConsent) ObtainKeys(ctx context.Context, browsers []Browser, reason string) ([]KeyOutcome, error) {
	items := make([]helper.VaultItem, len(browsers))
	for i, b := range browsers {
		items[i] = helper.VaultItem{Vault: vaultName(b), SafeStorageService: b.KeychainService}
	}
	res, err := c.Helper.VaultBatchRetrieve(ctx, items, ComposeBatchReason(browsers, reason))
	if err != nil {
		return nil, err
	}
	switch res.Code {
	case 0:
		return batchOutcomes(browsers, res)
	case 1:
		return nil, &ConsentError{Msg: "Touch ID authentication was cancelled or denied"}
	case 2:
		return bareOutcomes(ctx, browsers), nil
	case helper.CodePresenceUnavailable:
		return nil, &ConsentError{Msg: "the keychain keybag is locked (screen locked or no user present); retry after unlock", Err: ErrKeybagLocked}
	case helper.CodeCallerRejected:
		return nil, fmt.Errorf("vault-batch-retrieve rejected the caller or the invocation was malformed (exit %d); refusing to degrade to an unattended Keychain read: %s", res.Code, bytes.TrimSpace(res.Stderr))
	default:
		return nil, fmt.Errorf("vault-batch-retrieve exited %d: %s", res.Code, bytes.TrimSpace(res.Stderr))
	}
}

// batchOutcomes maps an approved vault-batch-retrieve's stdout lines onto
// browsers: ok derives the key from the secret exactly like the single path,
// missing marks the browser's outcome, error carries the failing OSStatus as
// the outcome's Err. The helper emits exactly one line per requested item, in
// order; anything else fails the whole batch.
func batchOutcomes(browsers []Browser, res helper.Result) ([]KeyOutcome, error) {
	lines, err := helper.ParseBatchLines(string(res.Stdout))
	if err != nil {
		return nil, err
	}
	if len(lines) != len(browsers) {
		return nil, fmt.Errorf("vault-batch-retrieve emitted %d lines for %d browsers", len(lines), len(browsers))
	}
	outcomes := make([]KeyOutcome, len(browsers))
	for i, line := range lines {
		if line.Index != i {
			return nil, fmt.Errorf("vault-batch-retrieve line %d reports index %d", i, line.Index)
		}
		outcome := KeyOutcome{Browser: browsers[i]}
		switch line.Status {
		case helper.BatchOK:
			outcome.Key = DeriveKey(SafeStorageKey(line.Payload))
		case helper.BatchMissing:
			outcome.Missing = true
		case helper.BatchError:
			outcome.Err = &ConsentError{Msg: fmt.Sprintf("Touch ID vault read for %q failed (OSStatus %d)", browsers[i].Display, line.OSStatus)}
		}
		outcomes[i] = outcome
	}
	return outcomes, nil
}

// bareOutcomes is the no-biometry-no-passcode fallback: each browser's Safe
// Storage password comes from a bare, non-interactive Keychain read. A failed
// read is that browser's outcome, never the whole batch's.
func bareOutcomes(ctx context.Context, browsers []Browser) []KeyOutcome {
	outcomes := make([]KeyOutcome, len(browsers))
	for i, b := range browsers {
		outcomes[i] = KeyOutcome{Browser: b}
		password, err := readSafeStorage(ctx, b.KeychainService)
		if err != nil {
			outcomes[i].Err = err
			continue
		}
		outcomes[i].Key = DeriveKey(password)
	}
	return outcomes
}

// readSafeStorage does the non-interactive `security find-generic-password -w -s
// <service>` read, trimming the surrounding whitespace (the CLI appends a
// trailing newline) to match the Python .strip().
func readSafeStorage(ctx context.Context, service string) (SafeStorageKey, error) {
	//nolint:gosec // G204: service is one of the tool's own Keychain service constants, not user-supplied.
	cmd := exec.CommandContext(ctx, securityBin, "find-generic-password", "-w", "-s", service)
	out, err := cmd.Output()
	if err != nil {
		return "", &ConsentError{Msg: fmt.Sprintf("could not read %q from the Keychain (denied or missing)", service), Err: err}
	}
	return SafeStorageKey(strings.TrimSpace(string(out))), nil
}
