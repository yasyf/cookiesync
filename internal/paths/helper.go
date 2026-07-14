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

// helperCask is the Homebrew cask that stages the signed helper bundle.
const helperCask = "cookiesync-keyhelper"

// brewPrefixes returns the Homebrew prefixes whose Caskroom may hold the staged
// helper bundle: $HOMEBREW_PREFIX first, then the Apple-silicon and Intel defaults.
func brewPrefixes() []string {
	prefixes := make([]string, 0, 3)
	if p := os.Getenv("HOMEBREW_PREFIX"); p != "" {
		prefixes = append(prefixes, p)
	}
	return append(prefixes, "/opt/homebrew", "/usr/local")
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

// HelperAppPath returns the cookiesync-keyhelper.app bundle. The cask stages it
// (stage_only) so the whole bundle lives intact in the Homebrew Caskroom — never
// /Applications — keeping its bundle-relative provisioning profile alongside the
// binary so the Secure Enclave keychain-access-group stays authorized. A
// *HelperError reports a bundle that is not staged.
func HelperAppPath() (string, error) {
	for _, prefix := range brewPrefixes() {
		matches, _ := filepath.Glob(filepath.Join(prefix, "Caskroom", helperCask, "*", helperApp))
		for _, app := range matches {
			if info, err := os.Stat(filepath.Join(app, "Contents", "MacOS", helperExecutable)); err == nil && info.Mode().IsRegular() {
				return app, nil
			}
		}
	}
	return "", &HelperError{Path: filepath.Join(brewPrefixes()[0], "Caskroom", helperCask)}
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
