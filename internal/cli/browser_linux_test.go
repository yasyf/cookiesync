package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestBrowserProfilesJSONLinux proves `browser profiles chromium --json` scans the XDG
// data root on Linux and emits the exported [{Dir,Name,Email}] array.
func TestBrowserProfilesJSONLinux(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	dataRoot := filepath.Join(xdg, "chromium")
	if err := os.MkdirAll(filepath.Join(dataRoot, "Default"), 0o700); err != nil {
		t.Fatalf("mkdir profile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataRoot, "Default", "Cookies"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write Cookies: %v", err)
	}
	localState := `{"profile":{"info_cache":{"Default":{"name":"VM","user_name":"vm@example.com"}}}}`
	if err := os.WriteFile(filepath.Join(dataRoot, "Local State"), []byte(localState), 0o600); err != nil {
		t.Fatalf("write Local State: %v", err)
	}

	out := runBrowserCmd(t, "profiles", "chromium", "--json")
	var got []struct{ Dir, Name, Email string }
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("profiles --json is not valid JSON: %v\n%s", err, out)
	}
	if len(got) != 1 || got[0].Dir != "Default" || got[0].Name != "VM" || got[0].Email != "vm@example.com" {
		t.Fatalf("profiles --json = %+v, want one Default/VM/vm@example.com entry", got)
	}
}
