package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	helperApp        = "cookiesync-keyhelper.app"
	helperExecutable = "cookiesync-keyhelper"
)

// HelperError reports that the signed Secure-Enclave helper is not installed;
// run 'cookiesync install' to fetch it. Callers fail closed on this rather than
// degrading to an unsigned fallback.
type HelperError struct {
	Path string
}

func (e *HelperError) Error() string {
	return fmt.Sprintf("cookiesync key helper not found at %s; run 'cookiesync install' to fetch the signed helper", e.Path)
}

// caskAppDirs are the Homebrew cask appdirs an app stanza may install into,
// most-specific first: /Applications by default, or ~/Applications when brew runs
// without admin rights.
func caskAppDirs() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home directory: %w", err)
	}
	return []string{"/Applications", filepath.Join(home, "Applications")}, nil
}

// helperBinaryOverride, when non-empty, short-circuits HelperBinary/RequireHelper
// to a fixed path. It is the seam consent and cache tests use to point the bridge
// at a fake helper script, mirroring the Python tests' monkeypatch of
// paths.helper_binary. SetHelperBinaryForTest installs and restores it.
var helperBinaryOverride string

// SetHelperBinaryForTest overrides the resolved helper binary path and returns a
// restore func. It exists solely for tests in sibling packages (consent, cache),
// which cannot reach an unexported var; production code never calls it.
func SetHelperBinaryForTest(path string) (restore func()) {
	prev := helperBinaryOverride
	helperBinaryOverride = path
	return func() { helperBinaryOverride = prev }
}

// HelperAppPath returns the cask-installed cookiesync-keyhelper.app bundle path:
// the first appdir that holds the bundle, falling back to the default appdir so a
// not-yet-installed helper still reports a stable path.
func HelperAppPath() (string, error) {
	dirs, err := caskAppDirs()
	if err != nil {
		return "", err
	}
	for _, dir := range dirs {
		app := filepath.Join(dir, helperApp)
		if info, statErr := os.Stat(app); statErr == nil && info.IsDir() {
			return app, nil
		}
	}
	return filepath.Join(dirs[0], helperApp), nil
}

// HelperBinary returns the signed helper's inner executable, e.g.
// …/cookiesync-keyhelper.app/Contents/MacOS/cookiesync-keyhelper.
func HelperBinary() (string, error) {
	if helperBinaryOverride != "" {
		return helperBinaryOverride, nil
	}
	app, err := HelperAppPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(app, "Contents", "MacOS", helperExecutable), nil
}

// RequireHelper returns the signed helper executable, or a *HelperError if it is
// not installed. The Secure-Enclave key vault and key cache run inside a
// Developer-ID-signed, notarized .app; an ad-hoc build is SIGKILLed at exec by
// AMFI and cannot touch the Enclave, so callers fail closed on a missing helper.
func RequireHelper() (string, error) {
	binary, err := HelperBinary()
	if err != nil {
		return "", err
	}
	if info, statErr := os.Stat(binary); statErr != nil || !info.Mode().IsRegular() {
		return "", &HelperError{Path: binary}
	}
	return binary, nil
}
