package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/cregistry"
	"github.com/yasyf/synckit/syncservice"
)

// registryServeCmd is the frozen remote command the Fetcher drives to read a peer's
// convergent endpoint registry: the peer's rpc-serve bridge, which forwards the typed
// svc.get_state call to the peer's resident helper and streams the registry JSON back
// byte-exact (so the registry's int64 CRDT stamps survive).
const registryServeCmd = "cookiesync rpc-serve"

// fetchTimeout bounds one peer registry read. svc.get_state is a pure registry read —
// normally sub-second — so a peer that cannot answer quickly is down for this pass
// rather than wedging the converge. A var so tests shrink it.
var fetchTimeout = 15 * time.Second

// stateGetter reads a peer's opaque registry state. It is the slice of the typed sync
// client the Fetcher consumes — defined here, where it is consumed, so a test injects a
// fake without spawning ssh.
type stateGetter interface {
	GetState(ctx context.Context) (syncservice.RawRegistry, error)
	Close() error
}

// SSHFetcher reads a peer's convergent endpoint registry READ-ONLY for the pull-merge
// step, by driving the peer's rpc-serve bridge over ssh-stdio with a typed svc.get_state
// call and parsing the registry JSON. It never mutates the peer — the only thing the
// converge orchestration ever writes is the LOCAL registry — which is the structural loop
// guard: this type has no write method. A per-peer failure is returned and skips that
// peer, so one unreachable host never aborts a pass.
type SSHFetcher struct {
	// dial opens a typed sync client to peer. Production dials the peer's rpc-serve
	// bridge over ssh-stdio; a test injects a fake that returns a canned registry.
	dial func(peer string) stateGetter
}

type registryEnvelope struct {
	ProtocolVersion uint64                                 `json:"protocol_version"`
	Browsers        cregistry.Registry[state.EndpointMeta] `json:"browsers"`
}

// NewSSHFetcher builds the peer-registry fetcher that dials each peer's rpc-serve bridge
// over ssh-stdio.
func NewSSHFetcher(runner syncservice.TransportRunner) SSHFetcher {
	return newSSHFetcher(func(peer string) stateGetter {
		return syncservice.NewClient(runner.SSHStdio(peer, registryServeCmd))
	})
}

// newSSHFetcher builds the fetcher over an injected dial, so a test drives Fetch against
// a fake stateGetter without spawning ssh.
func newSSHFetcher(dial func(peer string) stateGetter) SSHFetcher {
	return SSHFetcher{dial: dial}
}

// Fetch returns peer's current convergent endpoint registry without modifying it. It
// dials the peer's rpc-serve bridge, calls svc.get_state for the opaque registry bytes,
// and decodes them into the convergent registry the merge unions against.
func (f SSHFetcher) Fetch(ctx context.Context, peer string) (cregistry.Registry[state.EndpointMeta], error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	c := f.dial(peer)
	defer func() { _ = c.Close() }()
	raw, err := c.GetState(ctx)
	if err != nil {
		return nil, fmt.Errorf("get_state from %s: %w", peer, err)
	}
	var envelope registryEnvelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("parse registry from %s: %w", peer, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("parse registry from %s: trailing JSON", peer)
	}
	if envelope.ProtocolVersion != cookie.ProtocolVersion || envelope.Browsers == nil {
		return nil, fmt.Errorf("parse registry from %s: protocol version %d, want %d",
			peer, envelope.ProtocolVersion, cookie.ProtocolVersion)
	}
	return envelope.Browsers, nil
}

// MarshalRegistry encodes a convergent endpoint registry in the exact v1 envelope.
func MarshalRegistry(reg cregistry.Registry[state.EndpointMeta]) ([]byte, error) {
	return json.MarshalIndent(registryEnvelope{
		ProtocolVersion: cookie.ProtocolVersion,
		Browsers:        reg,
	}, "", "  ")
}
