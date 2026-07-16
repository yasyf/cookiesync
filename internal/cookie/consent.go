package cookie

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"unicode"

	"github.com/yasyf/cookiesync/internal/helper"
)

// securityBin is the macOS Keychain CLI used for the non-interactive Safe Storage
// read on hosts with no biometry/passcode, and for the owning-host unprompted
// release after a routed approval. It is a var so tests can point it at a fake.
var securityBin = "/usr/bin/security"

// reasonCap bounds the user-supplied reason that surfaces verbatim in the Touch ID
// dialog. The cap is applied to the collapsed reason, before the prompt prefix.
const reasonCap = 160

// ErrKeybagLocked reports that the keychain keybag was locked (screen locked or no
// user present) when the helper tried to release keys — retryable after unlock. It
// is wrapped by the ConsentError ObtainKeys returns on the helper's presence exit,
// so callers branch on it via errors.Is.
var ErrKeybagLocked = errors.New("keychain keybag locked")

// ErrBridgeVaultMissing reports that the strict-biometric bridge vault has no
// enrolled item — nothing to release, re-enroll needed. A routed approver treats
// it as unavailable (route on to another peer), never a denial. Callers branch
// on it via errors.Is.
var ErrBridgeVaultMissing = errors.New("bridge vault missing")

// ConsentError reports that the user explicitly declined the Touch ID / passcode
// prompt, or that a Keychain read or vault enrollment failed.
type ConsentError struct {
	Msg string
	Err error
}

func (e *ConsentError) Error() string { return e.Msg }

func (e *ConsentError) Unwrap() error { return e.Err }

// ComposeReason builds the Touch ID prompt text: concise and specific — what is
// unlocked, then a short why. reason is collapsed to a single line and capped,
// since it surfaces verbatim in the dialog. The output is byte-for-byte the
// Python compose_reason: "unlock your <host> cookies to <collapsed reason>".
func ComposeReason(host, reason string) string {
	collapsed := strings.Join(strings.FieldsFunc(reason, isPythonSpace), " ")
	if runes := []rune(collapsed); len(runes) > reasonCap {
		collapsed = string(runes[:reasonCap])
	}
	return fmt.Sprintf("unlock your %s cookies to %s", host, collapsed)
}

// ComposeBatchReason builds the one-sheet Touch ID prompt for a batch: every
// browser's display name joined with " + ", then the reason, through the same
// collapse-and-cap as ComposeReason — the cap truncates the reason tail, never
// the browser names. For one browser the output is byte-identical to
// ComposeReason.
func ComposeBatchReason(browsers []Browser, reason string) string {
	displays := make([]string, len(browsers))
	for i, b := range browsers {
		displays[i] = b.Display
	}
	return ComposeReason(strings.Join(displays, " + "), reason)
}

// isPythonSpace reports whether r is whitespace to Python's str.split(): the
// unicode.IsSpace set plus the C0 information separators FS/GS/RS/US
// (U+001C–U+001F), which Python's split treats as whitespace but unicode.IsSpace
// does not. Matching it keeps ComposeReason byte-identical to the Python oracle.
func isPythonSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1C && r <= 0x1F)
}

// KeyOutcome is one browser's result within an ObtainKeys batch: the derived
// key, or Missing when the browser has neither a vault item nor a Safe Storage
// password to enroll from, or Err when its read failed. At most one of Key,
// Missing, and Err is set.
type KeyOutcome struct {
	Browser Browser
	Key     AesKey
	Missing bool
	Err     error
}

// Consent obtains a browser's Safe Storage AES key, gating on the user's consent.
type Consent interface {
	// ObtainKey releases the key behind one Touch ID (or passcode) tap, with the
	// prompt explaining the given reason.
	ObtainKey(ctx context.Context, browser Browser, reason string) (AesKey, error)
	// ObtainKeys releases every browser's key behind a single Touch ID (or
	// passcode) tap whose prompt names all of them. Whole-batch failures — a
	// denied sheet, a locked keybag, a helper that cannot run — are the returned
	// error; per-browser results, index-aligned with browsers, are the outcomes.
	ObtainKeys(ctx context.Context, browsers []Browser, reason string) ([]KeyOutcome, error)
	// ObtainKeyUnprompted releases the key non-interactively via a bare Keychain
	// read, for the owning host only after a routed approval has already gated it.
	ObtainKeyUnprompted(ctx context.Context, browser Browser) (AesKey, error)
	// ObtainKeyBiometric releases the key behind a strict biometric-only tap, with
	// no passcode or non-interactive fallback — the gate the live CDP bridge uses.
	ObtainKeyBiometric(ctx context.Context, browser Browser, reason string) (AesKey, error)
}

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

// ObtainKeys releases every browser's Safe Storage key behind a single Touch ID
// (or passcode) sheet via vault-batch-retrieve, which enrolls a missing vault
// item in-helper under the same authentication — no probe, no second tap. A
// denied sheet or a locked keybag fails the whole batch with a ConsentError; a
// host with no biometry and no passcode degrades to bare per-browser Keychain
// reads. Every helper prompt on this path carries the composed reason, so the
// helper never shows its generic default.
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
