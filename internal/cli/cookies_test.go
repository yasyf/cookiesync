package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/cookiesync/internal/testutil"
)

// writeCookieStore creates an empty cookie store file at path, making its parent dirs.
func writeCookieStore(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { //nolint:gosec // G703: path is rooted in t.TempDir.
		t.Fatalf("mkdir store dir: %v", err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil { //nolint:gosec // G703: path is rooted in t.TempDir.
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

func TestCookiesHostReadsThatHostAlone(t *testing.T) {
	testutil.IsolateHostConfig(t, paths.Config)
	t.Setenv("HOME", t.TempDir())
	var calls []string
	var gotParams map[string]any
	orig := rpcCallJSON
	rpcCallJSON = func(_ context.Context, _ string, method string, params map[string]any, out any) error {
		calls = append(calls, method)
		gotParams = params
		return json.Unmarshal([]byte(fmt.Sprintf(`{"protocol_version":%d,"cookies":[]}`, cookie.ProtocolVersion)), out)
	}
	t.Cleanup(func() { rpcCallJSON = orig })

	run := func(args ...string) error {
		cmd := newCookiesCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(args)
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		return cmd.Execute()
	}

	if err := run("--host", "you@desktop", "https://app.slack.com"); err != nil {
		t.Fatalf("cookies --host: %v", err)
	}
	if len(calls) != 1 || calls[0] != "get_cookies" || gotParams["host"] != "you@desktop" {
		t.Fatalf("cookies --host called %v with %v, want one get_cookies naming you@desktop", calls, gotParams)
	}

	for _, refused := range []struct {
		args []string
		want string
	}{
		{[]string{"--host", "you@desktop", "--browser", "chrome", "https://app.slack.com"}, "drop --browser"},
		{[]string{"--host", "you@desktop", "--format", "webstorage", "https://app.slack.com"}, "drop --host"},
	} {
		calls = nil
		if err := run(refused.args...); err == nil || !strings.Contains(err.Error(), refused.want) {
			t.Fatalf("cookies %v = %v, want a refusal containing %q", refused.args, err, refused.want)
		}
		if len(calls) != 0 {
			t.Fatalf("cookies %v reached the daemon: %v", refused.args, calls)
		}
	}
}
