package bridge

import (
	"fmt"
	"os"
)

const chromeHostBinary = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

// ResolveHostBinary returns the Google Chrome executable path, erroring if
// Chrome is not installed.
func ResolveHostBinary() (string, error) {
	if _, err := os.Stat(chromeHostBinary); err != nil {
		return "", fmt.Errorf("google chrome not installed at %s: %w", chromeHostBinary, err)
	}
	return chromeHostBinary, nil
}
