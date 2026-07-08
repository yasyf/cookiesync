// Package cookie is the Go port of the Python cookiesync cookie subsystem: the
// data model and the Chrome macOS "Safe Storage" v10 cookie crypto.
//
// Timestamps stay Chrome-native (ChromeMicros, µs since 1601) throughout the model;
// conversion to Unix seconds happens only at serialize time.
package cookie

import (
	"math"
	"math/big"
	"time"
)

// Host is a bare hostname: lowercase, no leading dot.
type Host string

// HostKey is the host_key column from the Chrome cookie store. It may carry a
// leading dot (e.g. ".x.com") to denote a domain cookie.
type HostKey string

// SafeStorageKey is the raw "Safe Storage" password read from the macOS Keychain.
type SafeStorageKey string

// AesKey is the 16-byte AES-128 key derived from a SafeStorageKey.
type AesKey []byte

// ChromeMicros is a Chrome timestamp: microseconds since the Windows epoch (1601).
type ChromeMicros int64

// windowsEpochOffset is the seconds between the Windows epoch (1601-01-01) and the
// Unix epoch (1970-01-01); Chrome stores cookie timestamps as µs since 1601.
const windowsEpochOffset = 11_644_473_600

// unixToChromeMicros converts a wall-clock time to a Chrome timestamp (µs since 1601).
func unixToChromeMicros(t time.Time) ChromeMicros {
	return ChromeMicros((t.Unix()+windowsEpochOffset)*1_000_000 + int64(t.Nanosecond())/1_000)
}

// unixSecondsToChromeMicros converts Unix seconds (as a float, e.g. from get-cookie)
// to a Chrome timestamp, rounding half-to-even to match Python's round().
func unixSecondsToChromeMicros(seconds float64) ChromeMicros {
	return ChromeMicros(math.RoundToEven((seconds + windowsEpochOffset) * 1_000_000))
}

// chromeMicrosToUnix converts a Chrome timestamp to Unix seconds. A non-positive
// timestamp is a session cookie (no expiry), reported via the session return.
func chromeMicrosToUnix(micros ChromeMicros) (seconds float64, session bool) {
	if micros <= 0 {
		return 0, true
	}
	// Divide as an exact rational and round once: float64(micros)/1e6 would
	// double-round (int64->float64 loses precision above 2^53 µs, i.e. every real
	// expiry) and diverge from Python's exact-int division.
	r := new(big.Rat).SetFrac(big.NewInt(int64(micros)), big.NewInt(1_000_000))
	f, _ := r.Float64()
	return f - windowsEpochOffset, false
}

// samesiteToPlaywright maps Chrome's samesite int to Playwright's string. Chrome's
// unspecified (-1) and lax (1) both map to "Lax".
func samesiteToPlaywright(samesite int) string {
	switch samesite {
	case 0:
		return "None"
	case 2:
		return "Strict"
	default:
		return "Lax"
	}
}

// Cookie is one decrypted cookie, carrying Chrome-native column values.
type Cookie struct {
	HostKey              HostKey
	Name                 string
	Value                string
	Path                 string
	ExpiresUTC           ChromeMicros
	LastUpdateUTC        ChromeMicros
	CreationUTC          ChromeMicros
	IsSecure             bool
	IsHTTPOnly           bool
	SameSite             int
	SourceScheme         int
	SourcePort           int
	TopFrameSiteKey      string
	HasCrossSiteAncestor int
}

// EncryptedRow is a raw, pre-decrypt cookie row straight off the Chrome SQLite
// store. It carries both the EncryptedValue blob and the legacy plaintext Value
// column.
type EncryptedRow struct {
	HostKey              HostKey
	Name                 string
	EncryptedValue       []byte
	Value                string
	Path                 string
	ExpiresUTC           ChromeMicros
	LastUpdateUTC        ChromeMicros
	CreationUTC          ChromeMicros
	IsSecure             bool
	IsHTTPOnly           bool
	SameSite             int
	SourceScheme         int
	SourcePort           int
	TopFrameSiteKey      string
	HasCrossSiteAncestor int
}

// WebStorageEntry is one localStorage or sessionStorage item: a name/value pair
// decoded from a browser's LevelDB web-storage store.
type WebStorageEntry struct {
	Name  string
	Value string
}

// OriginStorage is one origin's captured web storage — its localStorage and
// sessionStorage — ready to inject into a headless browser session. IndexedDB is
// deferred: its idb_cmp1 comparator and V8-serialized values need a bespoke reader, so
// it is not read here.
type OriginStorage struct {
	Origin         string
	LocalStorage   []WebStorageEntry
	SessionStorage []WebStorageEntry
}

// StorageState is a bundle of decrypted cookies plus per-origin web storage, ready to
// seed a browser session.
type StorageState struct {
	Cookies []Cookie
	Origins []OriginStorage
}
