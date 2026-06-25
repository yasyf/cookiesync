package watch

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite" // register the sqlite driver for the test store

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/cregistry"
)

// fakeMesh points the shared mesh seam at a fake reposync that reports this self target
// and peers, so the notify fan-out resolves its hosts from reposync without a real
// reposync install.
func fakeMesh(t *testing.T, self string, peers ...string) {
	t.Helper()
	if peers == nil {
		peers = []string{}
	}
	payload, err := json.Marshal(struct {
		Version int      `json:"version"`
		Self    string   `json:"self"`
		Hosts   []string `json:"hosts"`
	}{1, self, peers})
	if err != nil {
		t.Fatalf("marshal mesh: %v", err)
	}
	script := filepath.Join(t.TempDir(), "reposync")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat <<'JSON'\n"+string(payload)+"\nJSON\n"), 0o755); err != nil { //nolint:gosec // the fake reposync must be executable.
		t.Fatalf("write fake reposync: %v", err)
	}
	prev := mesh.Bin
	mesh.Bin = script
	t.Cleanup(func() { mesh.Bin = prev })
}

// fixedStore is an EndpointLookup returning a fixed state snapshot, so the resolver
// and the loop run against a synthetic registry without touching disk.
type fixedStore struct {
	st *state.State
}

func (s fixedStore) Load(_ context.Context) (*state.State, error) { return s.st, nil }

// stateWith builds a State with the given self target and present endpoints, each
// stamped at a fixed time so the present set is deterministic.
func stateWith(self string, endpoints ...state.Endpoint) *state.State {
	reg := cregistry.New[state.EndpointMeta]()
	at := cregistry.UnixMicros(time.Unix(1, 0))
	for _, ep := range endpoints {
		reg.Add(string(ep.ID()), ep.Meta(), at)
	}
	return &state.State{SelfTarget: self, Settings: state.DefaultSettings(), Browsers: reg}
}

// v24Schema is a Chrome v24 cookie store schema, enough for a real fingerprint and
// apply round-trip against an ephemeral SQLite file.
const v24Schema = `
CREATE TABLE cookies (
    creation_utc INTEGER NOT NULL,
    host_key TEXT NOT NULL,
    top_frame_site_key TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    encrypted_value BLOB NOT NULL,
    path TEXT NOT NULL,
    expires_utc INTEGER NOT NULL,
    is_secure INTEGER NOT NULL,
    is_httponly INTEGER NOT NULL,
    last_access_utc INTEGER NOT NULL,
    has_expires INTEGER NOT NULL,
    is_persistent INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    samesite INTEGER NOT NULL,
    source_scheme INTEGER NOT NULL,
    source_port INTEGER NOT NULL,
    last_update_utc INTEGER NOT NULL,
    source_type INTEGER NOT NULL,
    has_cross_site_ancestor INTEGER NOT NULL
);
CREATE UNIQUE INDEX cookies_unique_index ON cookies(
    host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port
);
`

// chromeStoreUnderHome points HOME at a temp dir and creates an empty Chrome v24
// cookie store for the Default profile there, so cookie.Lookup("chrome") resolves to
// it. It returns the chrome Browser the resolver will fingerprint.
func chromeStoreUnderHome(t *testing.T) cookie.Browser {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	browser, err := cookie.Lookup("chrome")
	if err != nil {
		t.Fatalf("lookup chrome: %v", err)
	}
	if err := os.MkdirAll(browser.ProfileDir("Default"), 0o700); err != nil {
		t.Fatalf("mkdir profile: %v", err)
	}
	db, err := sql.Open("sqlite", browser.CookiesDB("Default"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(v24Schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return browser
}
