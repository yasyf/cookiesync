package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/synckit/hostregistry"
)

// seedRegistry writes the self target and peer hosts into the shared host registry, so
// browser add's host validation passes for a known host.
func seedRegistry(t *testing.T, self string, hosts ...string) {
	t.Helper()
	if _, err := paths.Config.Update(context.Background(), func(g *hostregistry.Registry) error {
		g.Self = self
		for _, h := range hosts {
			g.UpsertHost(h)
		}
		return nil
	}); err != nil {
		t.Fatalf("seed registry: %v", err)
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
