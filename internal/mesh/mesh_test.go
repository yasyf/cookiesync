package mesh

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// fakeReposync points Bin at a fake reposync that prints a host registry with this self
// target and peers, so Resolve reads a known mesh without a real reposync install.
func fakeReposync(t *testing.T, self string, peers ...string) {
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
		t.Fatalf("marshal registry: %v", err)
	}
	script := filepath.Join(t.TempDir(), "reposync")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat <<'JSON'\n"+string(payload)+"\nJSON\n"), 0o755); err != nil { //nolint:gosec // the fake reposync must be executable.
		t.Fatalf("write fake reposync: %v", err)
	}
	prev := Bin
	Bin = script
	t.Cleanup(func() { Bin = prev })
}

// TestResolveReturnsSelfAndPeers proves Resolve reads reposync's self target and the
// other hosts as the peer mesh — the set cookiesync converges across.
func TestResolveReturnsSelfAndPeers(t *testing.T) {
	fakeReposync(t, "me@laptop", "you@desktop", "她@air")

	self, peers, err := Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if self != "me@laptop" {
		t.Fatalf("self = %q, want me@laptop", self)
	}
	if len(peers) != 2 || peers[0] != "you@desktop" || peers[1] != "她@air" {
		t.Fatalf("peers = %v, want [you@desktop 她@air]", peers)
	}
}

// TestResolveNoPeersIsEmptySlice proves a single-host mesh resolves to self with no
// peers — a valid mesh, not an error.
func TestResolveNoPeersIsEmptySlice(t *testing.T) {
	fakeReposync(t, "solo@box")

	self, peers, err := Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if self != "solo@box" || len(peers) != 0 {
		t.Fatalf("Resolve = (%q, %v), want (solo@box, [])", self, peers)
	}
}

// TestResolveMissingReposyncErrors proves a missing reposync is a hard error — cookiesync
// fails loud rather than syncing an empty mesh.
func TestResolveMissingReposyncErrors(t *testing.T) {
	prev := Bin
	Bin = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { Bin = prev })

	if _, _, err := Resolve(context.Background()); err == nil {
		t.Fatal("Resolve with no reposync = nil error, want a hard error")
	}
}
