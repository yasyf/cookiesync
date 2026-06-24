package cookie

import (
	"bytes"
	"context"
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

// isPythonSpace reports whether r is whitespace to Python's str.split(): the
// unicode.IsSpace set plus the C0 information separators FS/GS/RS/US
// (U+001C–U+001F), which Python's split treats as whitespace but unicode.IsSpace
// does not. Matching it keeps ComposeReason byte-identical to the Python oracle.
func isPythonSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1C && r <= 0x1F)
}

// Consent obtains a browser's Safe Storage AES key, gating on the user's consent.
type Consent interface {
	// ObtainKey releases the key behind one Touch ID (or passcode) tap, with the
	// prompt explaining the given reason.
	ObtainKey(ctx context.Context, browser Browser, reason string) (AesKey, error)
	// ObtainKeyUnprompted releases the key non-interactively via a bare Keychain
	// read, for the owning host only after a routed approval has already gated it.
	ObtainKeyUnprompted(ctx context.Context, browser Browser) (AesKey, error)
}

// TouchIDConsent is a Secure-Enclave-bound key vault: one biometric tap unlocks
// the cached Safe Storage key. The biometric vault and re-store run inside the
// installed, Developer-ID-signed cookiesync-keyhelper.app via the helper bridge; a
// missing helper fails closed rather than degrading to an unsigned build.
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
// tap. It probes the vault, then branches: no biometry and no passcode falls back
// to a bare Keychain read; an existing vault prompts via vault-retrieve; otherwise
// it enrolls the vault first, then retrieves. The prompt always carries the
// composed reason so the helper never shows its generic default.
func (c TouchIDConsent) ObtainKey(ctx context.Context, browser Browser, reason string) (AesKey, error) {
	bridge := c.Helper
	vault := vaultName(browser)
	prompt := ComposeReason(browser.Display, reason)

	status, err := bridge.VaultStatus(ctx, vault)
	if err != nil {
		return nil, err
	}
	hasPasscode := bytes.Contains(status.Stdout, []byte("passcode=true"))
	hasVault := bytes.Contains(status.Stdout, []byte("vault=true"))

	switch {
	case status.Code == 2 && !hasPasscode:
		password, readErr := readSafeStorage(ctx, browser.KeychainService)
		if readErr != nil {
			return nil, readErr
		}
		return DeriveKey(password), nil
	case hasVault:
		return c.retrieve(ctx, vault, browser.KeychainService, prompt)
	default:
		if enrollErr := c.enroll(ctx, vault, browser.KeychainService); enrollErr != nil {
			return nil, enrollErr
		}
		return c.retrieve(ctx, vault, browser.KeychainService, prompt)
	}
}

// retrieve prompts Touch ID once and returns the derived key. On exit 2
// (errSecItemNotFound / errSecAuthFailed: the biometryCurrentSet ACL invalidated
// because the fingerprint set changed) it re-enrolls once and retries the prompt
// once, preserving the reason; a second failure is a ConsentError.
func (c TouchIDConsent) retrieve(ctx context.Context, vault, safeStorageService, reason string) (AesKey, error) {
	result, err := c.Helper.VaultRetrieve(ctx, vault, reason)
	if err != nil {
		return nil, err
	}
	switch result.Code {
	case 0:
		return DeriveKey(SafeStorageKey(result.Stdout)), nil
	case 1:
		return nil, &ConsentError{Msg: "Touch ID authentication was cancelled or denied"}
	default:
		if enrollErr := c.enroll(ctx, vault, safeStorageService); enrollErr != nil {
			return nil, enrollErr
		}
		second, secondErr := c.Helper.VaultRetrieve(ctx, vault, reason)
		if secondErr != nil {
			return nil, secondErr
		}
		if second.Code == 0 {
			return DeriveKey(SafeStorageKey(second.Stdout)), nil
		}
		return nil, &ConsentError{Msg: "Touch ID vault retrieval failed after re-enrollment"}
	}
}

// enroll stores the Safe Storage password into the biometry-bound vault. A
// non-zero exit surfaces as a ConsentError rather than a raw exit code.
func (c TouchIDConsent) enroll(ctx context.Context, vault, safeStorageService string) error {
	result, err := c.Helper.VaultEnroll(ctx, vault, safeStorageService)
	if err != nil {
		return err
	}
	if result.Code != 0 {
		return &ConsentError{Msg: fmt.Sprintf("could not enroll the Touch ID vault for %q (exit %d)", safeStorageService, result.Code)}
	}
	return nil
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
