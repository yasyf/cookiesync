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
// the XDG layout on Linux: with several Chrome profiles holding a cookie store under
// the google-chrome data root, the one primary profile, Default, registers.
func TestEnsureLocalEndpointsRegistersInstalledLinuxBrowsers(t *testing.T) {
	testutil.IsolateHostConfig(t, paths.Config)
	seedRegistry(t, "me@vm")

	xdg := os.Getenv("XDG_CONFIG_HOME")
	writeCookieStore(t, filepath.Join(xdg, "google-chrome", "Profile 3", "Cookies"))
	writeCookieStore(t, filepath.Join(xdg, "google-chrome", "Default", "Cookies"))

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
	want := map[string]bool{"me@vm:chrome:Default": true}
	if len(got) != len(want) {
		t.Fatalf("registered %v, want %v", got, want)
	}
	for id := range want {
		if !got[id] {
			t.Fatalf("endpoint %q not registered; got %v", id, got)
		}
	}
}
