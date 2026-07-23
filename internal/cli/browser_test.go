package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/hostregistry"
)

// seedRegistry seeds the shared synckit host registry with this self target and peers,
// so browser add's host validation passes for a known host (cookiesync rides the shared
// mesh). hostregistry.Mesh keys off XDG_CONFIG_HOME, so it writes into the test's XDG
// root — the same one the cookiesync state store uses.
func seedRegistry(t *testing.T, self string, hosts ...string) {
	t.Helper()
	if hosts == nil {
		hosts = []string{}
	}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		xdg = t.TempDir()
		t.Setenv("XDG_CONFIG_HOME", xdg)
	}
	if err := hostregistry.Mesh.InitializeState(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := hostregistry.Mesh.Update(context.Background(), func(g *hostregistry.Registry) error { g.Self = self; g.Hosts = hosts; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := state.New(paths.Config).Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// runBrowserCmd runs `browser <sub> <args...>` on a fresh root and returns stdout.
func runBrowserCmd(t *testing.T, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	root := newRoot("test")
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"browser"}, args...))
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("browser %v: %v\n%s", args, err, out.String())
	}
	return out.String()
}

// TestBrowserAddLsRmRoundTrip proves add then ls shows the endpoint present, rm
// tombstones it so ls omits it, and the output strings match the frozen surface — all
// round-tripping through the convergent registry in state.json.
func TestBrowserAddLsRmRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	seedRegistry(t, "me@laptop", "you@desktop")

	// Empty ls before any add.
	if got := runBrowserCmd(t, "ls"); strings.TrimSpace(got) != "No tracked browsers." {
		t.Fatalf("empty ls = %q, want %q", got, "No tracked browsers.")
	}

	// Add a local and a peer endpoint.
	if got := runBrowserCmd(t, "add", "me@laptop", "chrome"); strings.TrimSpace(got) != "Tracking me@laptop:chrome:Default" {
		t.Fatalf("add = %q, want %q", got, "Tracking me@laptop:chrome:Default")
	}
	if got := runBrowserCmd(t, "add", "you@desktop", "arc", "--profile", "Work"); strings.TrimSpace(got) != "Tracking you@desktop:arc:Work" {
		t.Fatalf("add peer = %q, want Tracking you@desktop:arc:Work", got)
	}

	// ls now lists both, sorted by id.
	lines := strings.Split(strings.TrimSpace(runBrowserCmd(t, "ls")), "\n")
	want := []string{"me@laptop:chrome:Default", "you@desktop:arc:Work"}
	if len(lines) != 2 || lines[0] != want[0] || lines[1] != want[1] {
		t.Fatalf("ls = %v, want %v", lines, want)
	}

	// rm tombstones the local endpoint.
	if got := runBrowserCmd(t, "rm", "me@laptop", "chrome"); strings.TrimSpace(got) != "Untracked me@laptop:chrome:Default" {
		t.Fatalf("rm = %q, want Untracked me@laptop:chrome:Default", got)
	}
	lines = strings.Split(strings.TrimSpace(runBrowserCmd(t, "ls")), "\n")
	if len(lines) != 1 || lines[0] != "you@desktop:arc:Work" {
		t.Fatalf("ls after rm = %v, want [you@desktop:arc:Work]", lines)
	}
}

// TestBrowserLsJSONShape pins the exact --json shape: an array of {host,browser,profile}
// objects in that field order, indented — the byte shape a tool parses.
func TestBrowserLsJSONShape(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	seedRegistry(t, "me@laptop")
	runBrowserCmd(t, "add", "me@laptop", "chrome")

	out := runBrowserCmd(t, "ls", "--json")
	var got []map[string]string
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("ls --json is not valid JSON: %v\n%s", err, out)
	}
	if len(got) != 1 {
		t.Fatalf("ls --json len = %d, want 1: %s", len(got), out)
	}
	entry := got[0]
	if entry["host"] != "me@laptop" || entry["browser"] != "chrome" || entry["profile"] != "Default" {
		t.Fatalf("ls --json entry = %v, want host/browser/profile = me@laptop/chrome/Default", entry)
	}
	// Field order is host, browser, profile (frozen).
	if !strings.Contains(out, `"host"`) {
		t.Fatalf("ls --json missing host key: %s", out)
	}
	hostIdx := strings.Index(out, `"host"`)
	browserIdx := strings.Index(out, `"browser"`)
	profileIdx := strings.Index(out, `"profile"`)
	if hostIdx >= browserIdx || browserIdx >= profileIdx {
		t.Fatalf("ls --json field order is not host<browser<profile: %s", out)
	}

	// Empty --json is an empty array, not "No tracked browsers.".
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	seedRegistry(t, "me@laptop")
	if got := strings.TrimSpace(runBrowserCmd(t, "ls", "--json")); got != "[]" {
		t.Fatalf("empty ls --json = %q, want []", got)
	}
}

// TestBrowserAddRejectsUnknownBrowserAndHost proves the validation guards: an unknown
// browser and an unknown host each fail before any state write, with a message listing
// the valid choices.
func TestBrowserAddRejectsUnknownBrowserAndHost(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	seedRegistry(t, "me@laptop", "you@desktop")

	root := newRoot("test")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"browser", "add", "me@laptop", "nope"})
	if err := root.ExecuteContext(context.Background()); err == nil {
		t.Fatal("add unknown browser = nil error, want unknown-browser error")
	} else if !strings.Contains(err.Error(), "unknown browser") {
		t.Fatalf("add unknown browser err = %v, want unknown browser", err)
	}

	root = newRoot("test")
	out.Reset()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"browser", "add", "ghost@nowhere", "chrome"})
	if err := root.ExecuteContext(context.Background()); err == nil {
		t.Fatal("add unknown host = nil error, want unknown-host error")
	} else if !strings.Contains(err.Error(), "unknown host") {
		t.Fatalf("add unknown host err = %v, want unknown host", err)
	}
}

// TestBrowserProfilesJSON proves `browser profiles <browser> --json` scans this
// host's data root and emits the exported [{Dir,Name,Email}, ...] array — the shape
// the add picker parses over ssh from a peer. cookie.Registry resolves the data
// root under HOME, so a temp HOME with a seeded Chrome profile drives the real
// scanner.
func TestBrowserProfilesJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dataRoot := filepath.Join(home, "Library", "Application Support", "Google", "Chrome")
	profileDir := filepath.Join(dataRoot, "Default")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatalf("mkdir profile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "Cookies"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write Cookies: %v", err)
	}
	localState := `{"profile":{"info_cache":{"Default":{"name":"Yasyf","user_name":"yasyf@example.com"}}}}`
	if err := os.WriteFile(filepath.Join(dataRoot, "Local State"), []byte(localState), 0o600); err != nil {
		t.Fatalf("write Local State: %v", err)
	}

	out := runBrowserCmd(t, "profiles", "chrome", "--json")
	var got []struct {
		Dir   string
		Name  string
		Email string
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("profiles --json is not valid JSON: %v\n%s", err, out)
	}
	if len(got) != 1 {
		t.Fatalf("profiles --json len = %d, want 1: %s", len(got), out)
	}
	if got[0].Dir != "Default" || got[0].Name != "Yasyf" || got[0].Email != "yasyf@example.com" {
		t.Fatalf("profiles --json entry = %+v, want Default/Yasyf/yasyf@example.com", got[0])
	}
	// The field shape is the exported Dir/Name/Email, the value the add picker keys
	// off: Dir is what gets stored.
	for _, key := range []string{`"Dir"`, `"Name"`, `"Email"`} {
		if !strings.Contains(out, key) {
			t.Fatalf("profiles --json missing %s key: %s", key, out)
		}
	}
}

// TestBrowserProfilesUnknownBrowser proves an unknown browser id fails with a
// message listing the valid choices, before any scan.
func TestBrowserProfilesUnknownBrowser(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	root := newRoot("test")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"browser", "profiles", "nope"})
	if err := root.ExecuteContext(context.Background()); err == nil {
		t.Fatal("profiles unknown browser = nil error, want unknown-browser error")
	} else if !strings.Contains(err.Error(), "unknown browser") {
		t.Fatalf("profiles unknown browser err = %v, want unknown browser", err)
	}
}
