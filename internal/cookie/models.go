// Package cookie is the Go port of the Python cookiesync cookie subsystem: the
// data model and the Chrome macOS "Safe Storage" v10 cookie crypto.
//
// Timestamps stay Chrome-native (ChromeMicros, µs since 1601) throughout the model;
// conversion to Unix seconds happens only at serialize time.
package cookie

import "time"

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

// StorageState is a bundle of decrypted cookies, ready to seed a browser session.
type StorageState struct {
	Cookies []Cookie
}
