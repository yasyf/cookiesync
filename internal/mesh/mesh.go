// Package mesh bridges cookiesync's host mesh to reposync. cookiesync rides
// reposync's host registry: the set of hosts it converges across — this host plus
// every peer — is exactly what `reposync host ls --json` reports, never what
// cookiesync's own state happens to hold. A freshly-installed host has an empty
// cookiesync state but still belongs to the mesh, so the mesh must come from reposync
// for cross-host convergence to bootstrap.
package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

// Bin is the reposync CLI cookiesync reads its host mesh from. It is a var so tests can
// point it at a fake that prints a known host registry.
var Bin = "reposync"

// Resolve reads cookiesync's host mesh from reposync: self is this host's reposync
// target and peers are every OTHER host in the registry. A missing or erroring reposync
// is a hard error — cookiesync cannot converge a mesh it cannot read — never an empty
// mesh that would silently sync nothing.
func Resolve(ctx context.Context) (self string, peers []string, err error) {
	out, err := exec.CommandContext(ctx, Bin, "host", "ls", "--json").Output()
	if err != nil {
		return "", nil, fmt.Errorf("read reposync host registry (is reposync installed?): %w", err)
	}
	var reg struct {
		Self  string   `json:"self"`
		Hosts []string `json:"hosts"`
	}
	if err := json.Unmarshal(out, &reg); err != nil {
		return "", nil, fmt.Errorf("parse reposync host ls: %w", err)
	}
	return reg.Self, reg.Hosts, nil
}
