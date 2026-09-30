package cookie

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

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
