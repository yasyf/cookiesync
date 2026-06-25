package engine

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/cregistry"
)

// registryReadCmd is the frozen peer command the Fetcher shells to read a peer's
// convergent endpoint registry: it emits the browsers registry as JSON on stdout.
const registryReadCmd = "cookiesync state get-json"

// SSHFetcher reads a peer's convergent endpoint registry READ-ONLY for the pull-merge
// step, by shelling registryReadCmd over ssh and parsing the registry JSON. It never
// mutates the peer — the only thing the converge orchestration ever writes is the LOCAL
// registry — which is the structural loop guard: this type has no write method. A
// per-peer failure is returned and skips that peer, so one unreachable host never
// aborts a pass.
type SSHFetcher struct {
	runner SSHRunner
}

// NewSSHFetcher builds the peer-registry fetcher over runner.
func NewSSHFetcher(runner SSHRunner) SSHFetcher {
	return SSHFetcher{runner: runner}
}

// Fetch returns peer's current convergent endpoint registry without modifying it.
func (f SSHFetcher) Fetch(ctx context.Context, peer string) (cregistry.Registry[state.EndpointMeta], error) {
	out, err := f.runner.Run(ctx, peer, registryReadCmd, nil)
	if err != nil {
		return nil, err
	}
	reg := cregistry.New[state.EndpointMeta]()
	if err := json.Unmarshal([]byte(out), &reg); err != nil {
		return nil, fmt.Errorf("parse registry from %s: %w", peer, err)
	}
	return reg, nil
}

// MarshalRegistry encodes a convergent endpoint registry as the JSON the peer
// registryReadCmd emits — the byte shape the Fetcher round-trips.
func MarshalRegistry(reg cregistry.Registry[state.EndpointMeta]) ([]byte, error) {
	return json.MarshalIndent(reg, "", "  ")
}
