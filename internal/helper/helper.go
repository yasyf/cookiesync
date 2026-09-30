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
// unlock) / CodeCallerRejected (non-pinned caller or usage error — a hard
// failure, never degrade) contract and log the helper's stderr diagnostics.
package helper

import (
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

// CodeCallerRejected is the helper exit code for a non-pinned caller, a
// malformed invocation, or any misconfiguration — a hard failure cookiesync
// must never degrade to an unattended Keychain read on, distinct from the
// no-biometry exit 2 it may. It is authkit's caller-rejected code, kept under
// cookiesync's name alongside CodePresenceUnavailable.
const CodeCallerRejected = authkit.CodeCallerRejected

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
