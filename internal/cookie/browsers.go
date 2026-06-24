package cookie

import (
	"fmt"
	"os"
	"path/filepath"
)

// BrowserName is a browser's CLI/config identity (e.g. "chrome", "arc").
type BrowserName string

// Browser is a Chromium-family browser and its on-disk layout: where one
// profile keeps its cookie store and Local State, and the Keychain service
// holding its Safe Storage password.
type Browser struct {
	Name            BrowserName
	Display         string
	DataRoot        string
	KeychainService string
}

// ProfileDir is the directory holding one profile's state under this browser's
// data root.
func (b Browser) ProfileDir(profile string) string {
	return filepath.Join(b.DataRoot, profile)
}

// CookiesDB is the SQLite cookie store for one profile.
func (b Browser) CookiesDB(profile string) string {
	return filepath.Join(b.ProfileDir(profile), "Cookies")
}

// LocalState is the Local State JSON file at this browser's data root.
func (b Browser) LocalState() string {
	return filepath.Join(b.DataRoot, "Local State")
}

// Registry maps every supported browser to its on-disk layout, resolved against
// the current user's home directory ("~/Library/Application Support/...").
func Registry() (map[BrowserName]Browser, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home directory: %w", err)
	}
	appSupport := filepath.Join(home, "Library", "Application Support")
	return map[BrowserName]Browser{
		BrowserName("chrome"): {
			Name:            BrowserName("chrome"),
			Display:         "Chrome",
			DataRoot:        filepath.Join(appSupport, "Google", "Chrome"),
			KeychainService: "Chrome Safe Storage",
		},
		BrowserName("arc"): {
			Name:            BrowserName("arc"),
			Display:         "Arc",
			DataRoot:        filepath.Join(appSupport, "Arc", "User Data"),
			KeychainService: "Arc Safe Storage",
		},
	}, nil
}

// Lookup resolves one browser by name from the Registry.
func Lookup(name BrowserName) (Browser, error) {
	registry, err := Registry()
	if err != nil {
		return Browser{}, err
	}
	browser, ok := registry[name]
	if !ok {
		return Browser{}, fmt.Errorf("unknown browser %q", name)
	}
	return browser, nil
}
