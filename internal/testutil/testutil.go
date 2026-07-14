// Package testutil holds cross-package test helpers. It is imported only from
// _test.go files, so it never links into a production binary.
package testutil

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/synckit/hostregistry"
)

// IsolateHostConfig roots cfg under a per-test temporary directory and verifies the
// directory hostregistry actually resolves cannot escape that root, then returns it. It
// neutralizes a leaked config-dir override and points XDG_CONFIG_HOME at the temp root,
// so a test store never touches the developer's real config. A guarded test must not
// call t.Parallel — t.Setenv forbids it.
func IsolateHostConfig(t *testing.T, cfg hostregistry.Config) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv(paths.ConfigDirEnv, "")
	t.Setenv("XDG_CONFIG_HOME", root)
	dir, err := cfg.Dir()
	if err != nil {
		t.Fatalf("resolve config dir under %s: %v", root, err)
	}
	escaped, err := dirEscapes(root, dir)
	if err != nil {
		t.Fatalf("check config dir %s against root %s: %v", dir, root, err)
	}
	if escaped {
		t.Fatalf("config dir %s escapes test root %s", dir, root)
	}
	return dir
}

func dirEscapes(root, dir string) (bool, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false, fmt.Errorf("abs root %s: %w", root, err)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false, fmt.Errorf("abs dir %s: %w", dir, err)
	}
	rel, err := filepath.Rel(absRoot, absDir)
	if err != nil {
		return false, fmt.Errorf("relate %s to %s: %w", absDir, absRoot, err)
	}
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel), nil
}
