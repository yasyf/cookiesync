package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBrowserProfilesJSON proves `browser profiles <browser> --json` scans this
// host's data root and emits the exported [{Dir,Name,Email}, ...] array — the shape
// the add picker parses over ssh from a peer. cookie.Registry resolves the data
// root under HOME, so a temp HOME with a seeded Chrome profile drives the real
// scanner.
func TestBrowserProfilesJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dataRoot := filepath.Join(home, "Library", "Application Support", "Google", "Chrome")
	profileDir := filepath.Join(dataRoot, "Default")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatalf("mkdir profile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "Cookies"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write Cookies: %v", err)
	}
	localState := `{"profile":{"info_cache":{"Default":{"name":"Yasyf","user_name":"yasyf@example.com"}}}}`
	if err := os.WriteFile(filepath.Join(dataRoot, "Local State"), []byte(localState), 0o600); err != nil {
		t.Fatalf("write Local State: %v", err)
	}

	out := runBrowserCmd(t, "profiles", "chrome", "--json")
	var got []struct {
		Dir   string
		Name  string
		Email string
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("profiles --json is not valid JSON: %v\n%s", err, out)
	}
	if len(got) != 1 {
		t.Fatalf("profiles --json len = %d, want 1: %s", len(got), out)
	}
	if got[0].Dir != "Default" || got[0].Name != "Yasyf" || got[0].Email != "yasyf@example.com" {
		t.Fatalf("profiles --json entry = %+v, want Default/Yasyf/yasyf@example.com", got[0])
	}
	// The field shape is the exported Dir/Name/Email, the value the add picker keys
	// off: Dir is what gets stored.
	for _, key := range []string{`"Dir"`, `"Name"`, `"Email"`} {
		if !strings.Contains(out, key) {
			t.Fatalf("profiles --json missing %s key: %s", key, out)
		}
	}
}
