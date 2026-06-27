package cookie

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// arcSystemProfile is the name Arc gives its internal, non-user profile in Local
// State; it carries a cookie store but must never be offered as a choice.
const arcSystemProfile = "__ARC_SYSTEM_PROFILE"

// BrowserName is a browser's CLI/config identity (e.g. "chrome", "arc").
type BrowserName string

// Profile is one tracked browser profile: its on-disk directory (the value that
// keys the cookie store and is recorded in state) enriched with the display name
// and account email read from the browser's Local State.
type Profile struct {
	Dir   string
	Name  string
	Email string
}

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

// profileInfo is the subset of one Local State info_cache entry this package
// reads: the human-facing display name and the signed-in account's email.
type profileInfo struct {
	Name     string `json:"name"`
	UserName string `json:"user_name"`
}

// Profiles scans the immediate subdirectories of this browser's data root and
// returns, sorted by directory, those that hold a cookie store — the set this
// host could track — enriched with the display name and account email from Local
// State. The layout differs per browser (Chrome uses "Default" and "Profile N",
// Arc names them otherwise), so membership is decided by the presence of a
// CookiesDB rather than a fixed profile list. Arc's internal system profile is
// dropped, and a directory absent from info_cache falls back to its directory
// name with no email. A missing data root yields no profiles.
func (b Browser) Profiles() ([]Profile, error) {
	entries, err := os.ReadDir(b.DataRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan %s profiles: %w", b.Name, err)
	}
	infoCache, err := b.infoCache()
	if err != nil {
		return nil, err
	}
	var profiles []Profile
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if info, err := os.Stat(b.CookiesDB(entry.Name())); err != nil || info.IsDir() {
			continue
		}
		dir := entry.Name()
		info := infoCache[dir]
		if info.Name == arcSystemProfile {
			continue
		}
		name := info.Name
		if name == "" {
			name = dir
		}
		profiles = append(profiles, Profile{Dir: dir, Name: name, Email: info.UserName})
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Dir < profiles[j].Dir })
	return profiles, nil
}

// infoCache reads profile.info_cache from this browser's Local State, keyed by
// profile directory. A missing Local State yields an empty map, leaving every
// profile to fall back to its directory name.
func (b Browser) infoCache() (map[string]profileInfo, error) {
	raw, err := os.ReadFile(b.LocalState())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s local state: %w", b.Name, err)
	}
	var state struct {
		Profile struct {
			InfoCache map[string]profileInfo `json:"info_cache"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("parse %s local state: %w", b.Name, err)
	}
	return state.Profile.InfoCache, nil
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
