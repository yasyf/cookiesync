// Package mesh resolves cookiesync's host mesh from the shared synckit host
// registry. cookiesync rides the single mesh every synckit consumer registers
// against: the set of hosts it converges across — this host (self) plus every peer
// — is exactly what the shared ~/.config/synckit/state.json reports, never what
// cookiesync's own state happens to hold. A freshly-installed host has an empty
// cookiesync state but still belongs to the mesh, so the mesh must come from the
// shared registry for cross-host convergence to bootstrap.
package mesh

import (
	"context"
	"fmt"

	"github.com/yasyf/synckit/hostregistry"
)

// Resolve reads cookiesync's host mesh from the shared synckit registry: self is
// this host's ssh target and peers is every other registered host. An empty self
// is a hard error — cookiesync cannot key endpoints or converge a mesh it has not
// joined — never an empty mesh that would silently sync nothing.
func Resolve(_ context.Context) (self string, peers []string, err error) {
	reg, err := hostregistry.Mesh.Load()
	if err != nil {
		return "", nil, fmt.Errorf("read synckit host mesh (run 'synckitd register' to join): %w", err)
	}
	if reg.Self == "" {
		return "", nil, fmt.Errorf("this host has not joined the synckit mesh (run 'synckitd register')")
	}
	return reg.Self, reg.Hosts, nil
}
