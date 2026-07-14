package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/cookiesync/internal/testutil"
)

// writeCookieStore creates an empty cookie store file at path, making its parent dirs.
func writeCookieStore(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir store dir: %v", err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write cookie store: %v", err)
	}
}

// TestCookiesProfileWithoutBrowserErrors proves --profile without --browser fails fast,
// before any daemon call (decision 5): the profile flag only means something for a
// single browser.
func TestCookiesProfileWithoutBrowserErrors(t *testing.T) {
	cmd := newCookiesCmd()
	cmd.SetArgs([]string{"--profile", "Work", "https://x.com"})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--profile requires --browser") {
		t.Fatalf("cookies --profile without --browser = %v, want '--profile requires --browser'", err)
	}
}

// TestEnsureLocalEndpointsRegistersInstalledBrowsers proves the auto-register picks one
// primary profile per installed browser: Chrome with no Default but a "Profile 3" store
// registers chrome:Profile 3, and Arc with a Default store registers arc:Default.
func TestEnsureLocalEndpointsRegistersInstalledBrowsers(t *testing.T) {
	testutil.IsolateHostConfig(t, paths.Config)
	home := t.TempDir()
	t.Setenv("HOME", home)
	seedRegistry(t, "me@laptop")

	appSupport := filepath.Join(home, "Library", "Application Support")
	writeCookieStore(t, filepath.Join(appSupport, "Google", "Chrome", "Profile 3", "Cookies"))
	writeCookieStore(t, filepath.Join(appSupport, "Arc", "User Data", "Default", "Cookies"))

	if err := ensureLocalEndpoints(context.Background()); err != nil {
		t.Fatalf("ensureLocalEndpoints: %v", err)
	}
	st, err := state.New(paths.Config).Load(context.Background())
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	got := map[string]bool{}
	for _, ep := range st.Endpoints() {
		if ep.Host != "me@laptop" {
			t.Fatalf("registered a non-local endpoint: %+v", ep)
		}
		got[string(ep.ID())] = true
	}
	for _, want := range []string{"me@laptop:arc:Default", "me@laptop:chrome:Profile 3"} {
		if !got[want] {
			t.Fatalf("endpoint %q not registered; got %v", want, got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("registered %d endpoints, want 2: %v", len(got), got)
	}
}

// TestEnsureLocalEndpointsNoOpWhenLocalPresent proves a pre-existing local endpoint short
// circuits the auto-register: nothing new is added even with installed browsers unread.
func TestEnsureLocalEndpointsNoOpWhenLocalPresent(t *testing.T) {
	testutil.IsolateHostConfig(t, paths.Config)
	t.Setenv("HOME", t.TempDir())
	seedRegistry(t, "me@laptop")
	store := state.New(paths.Config)
	seeded := state.Endpoint{Host: "me@laptop", Browser: "chrome", Profile: "Work"}
	if err := store.AddBrowser(context.Background(), "me@laptop", seeded); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}

	if err := ensureLocalEndpoints(context.Background()); err != nil {
		t.Fatalf("ensureLocalEndpoints: %v", err)
	}
	st, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(st.Endpoints()) != 1 || string(st.Endpoints()[0].ID()) != "me@laptop:chrome:Work" {
		t.Fatalf("ensureLocalEndpoints mutated the registry: %v", st.Endpoints())
	}
}

// TestEnsureLocalEndpointsErrorsWithNoInstalledBrowsers proves an empty HOME (no browser
// stores) errors rather than registering nothing silently.
func TestEnsureLocalEndpointsErrorsWithNoInstalledBrowsers(t *testing.T) {
	testutil.IsolateHostConfig(t, paths.Config)
	t.Setenv("HOME", t.TempDir())
	seedRegistry(t, "me@laptop")

	err := ensureLocalEndpoints(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no installed browsers detected") {
		t.Fatalf("ensureLocalEndpoints with no browsers = %v, want 'no installed browsers detected'", err)
	}
}
