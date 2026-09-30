package cli

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/cookiesync/internal/testutil"
)

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
