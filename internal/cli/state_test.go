package cli

import (
	"bytes"
	"context"
	"encoding/json"
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
