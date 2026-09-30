package cookie

import (
	"fmt"
	"os"
	"path/filepath"
)

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
