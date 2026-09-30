package cookie

import (
	"path/filepath"
	"testing"
)

func TestRegistryLinuxUsesXDGConfigHome(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))
	xdg := filepath.Join(t.TempDir(), "xdg")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	registry, err := Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	want := map[BrowserName]Browser{
		"chrome":   {Name: "chrome", Display: "Chrome", DataRoot: filepath.Join(xdg, "google-chrome"), SecretServiceApplication: "chrome"},
		"chromium": {Name: "chromium", Display: "Chromium", DataRoot: filepath.Join(xdg, "chromium"), SecretServiceApplication: "chromium"},
	}
	if len(registry) != len(want) {
		t.Fatalf("Registry() = %#v, want %#v", registry, want)
	}
	for name, browser := range want {
		if registry[name] != browser {
			t.Fatalf("Registry()[%s] = %#v, want %#v", name, registry[name], browser)
		}
	}
	if _, err := Lookup("arc"); err == nil {
		t.Fatal("Arc has no Linux build and must not resolve")
	}
	if registry["chrome"].CookiesDB("Default") != filepath.Join(xdg, "google-chrome", "Default", "Cookies") {
		t.Fatalf("CookiesDB = %s", registry["chrome"].CookiesDB("Default"))
	}
}

func TestRegistryLinuxFallsBackToDotConfig(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	browser, err := Lookup("chromium")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if want := filepath.Join(home, ".config", "chromium"); browser.DataRoot != want {
		t.Fatalf("DataRoot = %s, want %s", browser.DataRoot, want)
	}
}
