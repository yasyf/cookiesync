package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/cregistry"
)

// TestStateGetJSONEmitsRegistry proves `cookiesync state get-json` reads state.json
// directly and emits the convergent browser-endpoint registry JSON that a peer's
// converge pull-merges — including a tombstone, so a remote delete propagates. It runs
// against an isolated XDG_CONFIG_HOME, never the live config.
func TestStateGetJSONEmitsRegistry(t *testing.T) {
	ctx := context.Background()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	store := state.New(paths.Config)
	live := state.Endpoint{Host: "me@laptop", Browser: "chrome", Profile: "Default"}
	if err := store.AddBrowser(ctx, "me@laptop", live); err != nil {
		t.Fatalf("AddBrowser: %v", err)
	}

	var out bytes.Buffer
	cmd := newStateGetJSONCmd()
	cmd.SetOut(&out)
	cmd.SetArgs(nil)
	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("state get-json: %v", err)
	}

	// The output decodes back into a convergent registry whose present set is exactly
	// the tracked endpoint — the byte shape the SSHFetcher round-trips.
	var reg cregistry.Registry[state.EndpointMeta]
	if err := json.Unmarshal(out.Bytes(), &reg); err != nil {
		t.Fatalf("decode emitted registry: %v (%s)", err, out.String())
	}
	present := reg.Present()
	if len(present) != 1 {
		t.Fatalf("present endpoints = %d, want 1: %s", len(present), out.String())
	}
	entry, ok := present[string(live.ID())]
	if !ok {
		t.Fatalf("emitted registry missing %s: %s", live.ID(), out.String())
	}
	if entry.Value.Host != "me@laptop" || entry.Value.Browser != "chrome" || entry.Value.Profile != "Default" {
		t.Fatalf("endpoint meta = %+v, want me@laptop/chrome/Default", entry.Value)
	}
}

// TestStateApplyJSONMergesStdin proves `cookiesync state apply-json` reads a convergent
// registry from stdin, MERGES it into local state (a local-only endpoint survives, a
// peer-only one is admitted), and emits {"applied": N} for the present count.
func TestStateApplyJSONMergesStdin(t *testing.T) {
	ctx := context.Background()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	store := state.New(paths.Config)
	localOnly := state.Endpoint{Host: "me@laptop", Browser: "chrome", Profile: "Default"}
	if err := store.AddBrowser(ctx, "me@laptop", localOnly); err != nil {
		t.Fatalf("AddBrowser: %v", err)
	}

	// The incoming registry advertises a peer endpoint the local state has not seen.
	incoming := cregistry.New[state.EndpointMeta]()
	peerOnly := state.Endpoint{Host: "you@desktop", Browser: "arc", Profile: "Work"}
	incoming.Add(string(peerOnly.ID()), peerOnly.Meta(), 9_000_000_000)
	body, err := json.Marshal(incoming)
	if err != nil {
		t.Fatalf("marshal incoming: %v", err)
	}

	var out bytes.Buffer
	cmd := newStateApplyJSONCmd()
	cmd.SetOut(&out)
	cmd.SetIn(strings.NewReader(string(body)))
	cmd.SetArgs(nil)
	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("state apply-json: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != `{"applied":2}` {
		t.Fatalf("apply-json output = %q, want {\"applied\":2}", got)
	}

	// Both endpoints are now present in local state — the merge was not destructive.
	st, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load after apply: %v", err)
	}
	if !st.Browsers[string(localOnly.ID())].Present() {
		t.Fatalf("local-only endpoint dropped by apply-json merge")
	}
	if !st.Browsers[string(peerOnly.ID())].Present() {
		t.Fatalf("peer-only endpoint not admitted by apply-json merge")
	}
}
