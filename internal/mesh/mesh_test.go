package mesh

import (
	"context"
	"testing"

	"github.com/yasyf/synckit/hostregistry"
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
	if err := hostregistry.Mesh.InitializeState(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, host := range hosts {
		fact, err := hostregistry.NewSSHHostFact(host, "/usr/local/bin/synckitd", []string{host})
		if err != nil {
			t.Fatal(err)
		}
		if err := hostregistry.Mesh.RegisterHost(context.Background(), fact); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := hostregistry.Mesh.Update(context.Background(), func(g *hostregistry.Registry) error { g.Self = self; g.Hosts = hosts; return nil }); err != nil {
		t.Fatal(err)
	}
}

// TestResolveReturnsSelfAndPeers proves Resolve reads the mesh self target and the
// other hosts as the peer mesh — the set cookiesync converges across.
func TestResolveReturnsSelfAndPeers(t *testing.T) {
	writeMesh(t, "me@laptop", "you@desktop", "she@air")

	self, peers, err := Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if self != "me@laptop" {
		t.Fatalf("self = %q, want me@laptop", self)
	}
	if len(peers) != 2 || peers[0] != "you@desktop" || peers[1] != "she@air" {
		t.Fatalf("peers = %v, want [you@desktop she@air]", peers)
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
