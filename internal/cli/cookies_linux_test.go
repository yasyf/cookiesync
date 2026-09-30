package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/cookiesync/internal/testutil"
)

// TestEnsureLocalEndpointsRegistersInstalledLinuxBrowsers proves the auto-register reads
// the XDG layout on Linux: Chrome with no Default but a "Profile 3" store registers
// chrome:Profile 3, and Chromium with a Default store registers chromium:Default.
func TestEnsureLocalEndpointsRegistersInstalledLinuxBrowsers(t *testing.T) {
	testutil.IsolateHostConfig(t, paths.Config)
	seedRegistry(t, "me@vm")

	xdg := os.Getenv("XDG_CONFIG_HOME")
	writeCookieStore(t, filepath.Join(xdg, "google-chrome", "Profile 3", "Cookies"))
	writeCookieStore(t, filepath.Join(xdg, "chromium", "Default", "Cookies"))

	if err := ensureLocalEndpoints(context.Background()); err != nil {
		t.Fatalf("ensureLocalEndpoints: %v", err)
	}
	st, err := state.New(paths.Config).Load(context.Background())
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	got := map[string]bool{}
	for _, ep := range st.Endpoints() {
		got[string(ep.ID())] = true
	}
	want := map[string]bool{"me@vm:chrome:Profile 3": true, "me@vm:chromium:Default": true}
	if len(got) != len(want) {
		t.Fatalf("registered %v, want %v", got, want)
	}
	for id := range want {
		if !got[id] {
			t.Fatalf("endpoint %q not registered; got %v", id, got)
		}
	}
}
