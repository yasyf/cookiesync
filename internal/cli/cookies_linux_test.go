package cli

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/cookiesync/internal/testutil"
)

func snapshotTree(t *testing.T, fsys fs.FS) map[string]string {
	t.Helper()
	tree := map[string]string{}
	err := fs.WalkDir(fsys, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			tree[path] = info.Mode().String()
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		tree[path] = info.Mode().String() + " " + string(data)
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return tree
}

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

// TestEnsureLocalEndpointsOnAFreshVMWritesNothing proves a Linux host with no Chrome
// data root at all returns without error and leaves no trace: no data root, no
// endpoint, and every path under the config home and HOME unchanged.
func TestEnsureLocalEndpointsOnAFreshVMWritesNothing(t *testing.T) {
	testutil.IsolateHostConfig(t, paths.Config)
	home := t.TempDir()
	t.Setenv("HOME", home)
	seedRegistry(t, "agent@vm")
	xdgFS, homeFS := os.DirFS(os.Getenv("XDG_CONFIG_HOME")), os.DirFS(home)
	beforeXDG, beforeHome := snapshotTree(t, xdgFS), snapshotTree(t, homeFS)

	if err := ensureLocalEndpoints(context.Background()); err != nil {
		t.Fatalf("ensureLocalEndpoints on a fresh VM = %v, want nil", err)
	}
	if _, err := fs.Stat(xdgFS, "google-chrome"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stat google-chrome data root = %v, want not exist", err)
	}
	st, err := state.New(paths.Config).Load(context.Background())
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if eps := st.Endpoints(); len(eps) != 0 {
		t.Fatalf("registered %v, want no endpoint", eps)
	}
	if after := snapshotTree(t, xdgFS); !reflect.DeepEqual(after, beforeXDG) {
		t.Fatalf("config home after = %v, want unchanged %v", after, beforeXDG)
	}
	if after := snapshotTree(t, homeFS); !reflect.DeepEqual(after, beforeHome) {
		t.Fatalf("HOME after = %v, want unchanged %v", after, beforeHome)
	}
}
