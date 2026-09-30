package cookie

import (
	"fmt"
	"os"
	"path/filepath"
)

// Registry maps every supported browser to its on-disk layout under the XDG config
// home ("$XDG_CONFIG_HOME" or "~/.config"), the base Chromium resolves its user
// data directory against. Only browsers a Mac approver also registers are
// ConsentRoutable; Chromium returns once the Mac side can approve it.
func Registry() (map[BrowserName]Browser, error) {
	configHome, err := xdgConfigHome()
	if err != nil {
		return nil, err
	}
	return map[BrowserName]Browser{
		BrowserName("chrome"): {
			Name:                     BrowserName("chrome"),
			Display:                  "Chrome",
			DataRoot:                 filepath.Join(configHome, "google-chrome"),
			SecretServiceApplication: "chrome",
			ConsentRoutable:          true,
		},
	}, nil
}

func xdgConfigHome() (string, error) {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".config"), nil
}
