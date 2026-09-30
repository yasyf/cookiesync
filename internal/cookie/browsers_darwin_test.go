package cookie

import (
	"path/filepath"
	"testing"
)

func TestRegistryDarwinUsesApplicationSupport(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "ignored"))
	registry, err := Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	appSupport := filepath.Join(home, "Library", "Application Support")
	want := map[BrowserName]Browser{
		"chrome": {Name: "chrome", Display: "Chrome", DataRoot: filepath.Join(appSupport, "Google", "Chrome"), KeychainService: "Chrome Safe Storage"},
		"arc":    {Name: "arc", Display: "Arc", DataRoot: filepath.Join(appSupport, "Arc", "User Data"), KeychainService: "Arc Safe Storage"},
	}
	if len(registry) != len(want) {
		t.Fatalf("Registry() = %#v, want %#v", registry, want)
	}
	for name, browser := range want {
		if registry[name] != browser {
			t.Fatalf("Registry()[%s] = %#v, want %#v", name, registry[name], browser)
		}
	}
	if _, err := Lookup("chromium"); err == nil {
		t.Fatal("chromium is registered on no platform: Darwin holds chrome and arc, Linux holds chrome")
	}
}
