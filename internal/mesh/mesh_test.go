package mesh

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeMesh seeds the shared synckit host registry under a temp XDG_CONFIG_HOME so
// Resolve reads a known mesh without a real registration. hostregistry.Mesh keys off
// XDG_CONFIG_HOME, so a t.Setenv isolates each test's mesh.
func writeMesh(t *testing.T, self string, hosts ...string) {
	t.Helper()
	if hosts == nil {
		hosts = []string{}
	}
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	dir := filepath.Join(cfg, "synckit")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir synckit: %v", err)
	}
	payload, err := json.Marshal(struct {
		Self  string   `json:"self"`
		Hosts []string `json:"hosts"`
	}{self, hosts})
	if err != nil {
		t.Fatalf("marshal mesh: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), payload, 0o600); err != nil {
		t.Fatalf("write mesh state: %v", err)
	}
}

// TestResolveReturnsSelfAndPeers proves Resolve reads the mesh self target and the
// other hosts as the peer mesh — the set cookiesync converges across.
func TestResolveReturnsSelfAndPeers(t *testing.T) {
	writeMesh(t, "me@laptop", "you@desktop", "她@air")

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
	writeMesh(t, "solo@box")

	self, peers, err := Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if self != "solo@box" || len(peers) != 0 {
		t.Fatalf("Resolve = (%q, %v), want (solo@box, [])", self, peers)
	}
}

// TestResolveUnjoinedMeshErrors proves an empty self (this host has not joined the
// mesh) is a hard error — cookiesync fails loud rather than keying on an empty self.
func TestResolveUnjoinedMeshErrors(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if _, _, err := Resolve(context.Background()); err == nil {
		t.Fatal("Resolve with no mesh = nil error, want a hard error")
	}
}
