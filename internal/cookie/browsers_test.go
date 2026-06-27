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

	// Two profiles carry a Cookies store; one subdir lacks one; one entry is a
	// plain file (not a profile dir); and one directory named like the store sits
	// at the data root, which must not be mistaken for a profile's store.
	withStore := []string{"Default", "Profile 1"}
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
	if err := os.WriteFile(filepath.Join(root, "Local State"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write Local State: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "Cookies"), 0o750); err != nil {
		t.Fatalf("mkdir Cookies: %v", err)
	}

	got, err := b.Profiles()
	if err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	want := []string{"Default", "Profile 1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Profiles() = %v, want %v", got, want)
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
