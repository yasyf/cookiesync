package cookie

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestBrowserProfiles(t *testing.T) {
	root := t.TempDir()
	b := Browser{Name: BrowserName("test"), DataRoot: root}

	// Four directories carry a Cookies store: a normal profile with a display name
	// and email, Arc's internal system profile (must be dropped), and one absent
	// from info_cache (must fall back to its dir name with no email). One subdir
	// lacks a store; one entry is a plain file (not a profile dir); and one
	// directory named like the store sits at the data root, which must not be
	// mistaken for a profile's store.
	withStore := []string{"Default", "Profile 1", "Profile 2", "Untracked"}
	for _, name := range withStore {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "Cookies"), []byte("x"), 0o600); err != nil {
			t.Fatalf("write Cookies in %s: %v", name, err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "System Profile"), 0o750); err != nil {
		t.Fatalf("mkdir System Profile: %v", err)
	}
	localState := `{"profile":{"info_cache":{` +
		`"Default":{"name":"Yasyf","user_name":"yasyf@example.com"},` +
		`"Profile 1":{"name":"__ARC_SYSTEM_PROFILE"},` +
		`"Profile 2":{"name":"Gmail","user_name":"yasyfm@gmail.com"}` +
		`}}}`
	if err := os.WriteFile(filepath.Join(root, "Local State"), []byte(localState), 0o600); err != nil {
		t.Fatalf("write Local State: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "Cookies"), 0o750); err != nil {
		t.Fatalf("mkdir Cookies: %v", err)
	}

	got, err := b.Profiles()
	if err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	want := []Profile{
		{Dir: "Default", Name: "Yasyf", Email: "yasyf@example.com"},
		{Dir: "Profile 2", Name: "Gmail", Email: "yasyfm@gmail.com"},
		{Dir: "Untracked", Name: "Untracked", Email: ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Profiles() = %#v, want %#v", got, want)
	}
}

func TestBrowserProfilesMissingRoot(t *testing.T) {
	b := Browser{Name: BrowserName("test"), DataRoot: filepath.Join(t.TempDir(), "absent")}
	got, err := b.Profiles()
	if err != nil {
		t.Fatalf("Profiles on missing root: %v", err)
	}
	if got != nil {
		t.Fatalf("Profiles() on missing root = %v, want nil", got)
	}
}
