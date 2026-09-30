package bridge

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const snapShimScanBytes = 64 << 10

var chromeCandidates = []string{"google-chrome-stable", "google-chrome", "chromium", "chromium-browser"}

// ResolveHostBinary returns the first Chrome or Chromium on the daemon's PATH,
// resolved through its symlinks to the exact file it names. A snap is passed
// over: its confinement cannot reach the bridge's data dir under ~/.config.
func ResolveHostBinary() (string, error) {
	for _, name := range chromeCandidates {
		found, err := exec.LookPath(name)
		if errors.Is(err, exec.ErrNotFound) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("locate %s: %w", name, err)
		}
		binary, err := filepath.EvalSymlinks(found)
		if err != nil {
			return "", fmt.Errorf("resolve %s: %w", found, err)
		}
		snap, err := snapStub(binary)
		if err != nil {
			return "", err
		}
		if !snap {
			return binary, nil
		}
	}
	return "", fmt.Errorf("no chrome or chromium on PATH (looked for %s; snap packages are skipped because their confinement cannot reach the bridge data dir): install google-chrome-stable or the distro chromium package",
		strings.Join(chromeCandidates, ", "))
}

func snapStub(binary string) (bool, error) {
	if strings.HasPrefix(binary, "/snap/") || filepath.Base(binary) == "snap" {
		return true, nil
	}
	f, err := os.Open(binary) //nolint:gosec // binary is the PATH candidate being vetted.
	if err != nil {
		return false, fmt.Errorf("inspect %s: %w", binary, err)
	}
	defer func() { _ = f.Close() }()
	head, err := io.ReadAll(io.LimitReader(f, snapShimScanBytes))
	if err != nil {
		return false, fmt.Errorf("inspect %s: %w", binary, err)
	}
	return bytes.HasPrefix(head, []byte("#!")) && bytes.Contains(head, []byte("/snap/")), nil
}
