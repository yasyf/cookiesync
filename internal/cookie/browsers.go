package cookie

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

// Profiles scans the immediate subdirectories of this browser's data root and
// returns, sorted, the names of those that hold a cookie store — the set this
// host could track. The layout differs per browser (Chrome uses "Default" and
// "Profile N", Arc names them otherwise), so membership is decided by the
// presence of a CookiesDB rather than a fixed profile list. A missing data root
// yields no profiles.
func (b Browser) Profiles() ([]string, error) {
	entries, err := os.ReadDir(b.DataRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan %s profiles: %w", b.Name, err)
	}
	var profiles []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if info, err := os.Stat(b.CookiesDB(entry.Name())); err != nil || info.IsDir() {
			continue
		}
		profiles = append(profiles, entry.Name())
	}
	sort.Strings(profiles)
	return profiles, nil
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
