package testutil

import (
	"path/filepath"
	"testing"
)

// TestDirEscapes proves the predicate the isolation guard trips on: a config dir under
// the temp root is allowed, while a non-temp or traversal-escaping dir — a sibling, an
// ancestor, an absolute path elsewhere, or a ".." that climbs out — is rejected.
func TestDirEscapes(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name    string
		dir     string
		escapes bool
	}{
		{"under root", filepath.Join(root, "cookiesync"), false},
		{"root itself", root, false},
		{"nested under root", filepath.Join(root, "a", "b"), false},
		{"parent of root", filepath.Dir(root), true},
		{"absolute elsewhere", "/etc", true},
		{"traversal climbs out", filepath.Join(root, "..", "escape"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := dirEscapes(root, tc.dir)
			if err != nil {
				t.Fatalf("dirEscapes(%q, %q): %v", root, tc.dir, err)
			}
			if got != tc.escapes {
				t.Fatalf("dirEscapes(%q, %q) = %v, want %v", root, tc.dir, got, tc.escapes)
			}
		})
	}
}
