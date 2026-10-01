package auth

import (
	"context"
	"time"

	"github.com/yasyf/cookiesync/internal/mesh"
	consentkit "github.com/yasyf/synckit/consent"
	"github.com/yasyf/synckit/presence"
)

// AwaitApprover blocks until this host's session is attended or an approver
// candidate answers a live whoami, re-reading each on its own interval, and
// returns ctx's error when neither turns live first. A failed probe is judged
// as routesConsent and the Router judge it.
func (b *Broker) AwaitApprover(ctx context.Context) error {
	local := time.NewTicker(b.LocalAwaitInterval)
	defer local.Stop()
	peers := time.NewTicker(b.PeerAwaitInterval)
	defer peers.Stop()
	live, err := b.localAttended(ctx)
	if err == nil && !live {
		live, err = b.peerLive(ctx)
	}
	for err == nil && !live {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-local.C:
			live, err = b.localAttended(ctx)
		case <-peers.C:
			live, err = b.peerLive(ctx)
		}
	}
	return err
}

func (b *Broker) localAttended(ctx context.Context) (bool, error) {
	snap, err := b.probe(ctx)
	if err != nil {
		return true, ctx.Err()
	}
	return presence.Attended(snap)
}

func (b *Broker) peerLive(ctx context.Context) (bool, error) {
	st, err := b.state.Load(ctx)
	if err != nil {
		return false, err
	}
	_, peers, err := mesh.Resolve(ctx)
	if err != nil {
		return false, err
	}
	for _, peer := range approvers(st, peers) {
		live, err := b.Router.Live(ctx, peer)
		if err != nil && !consentkit.ProbeRoutesAround(err) {
			return false, err
		}
		if err == nil && live {
			return true, nil
		}
	}
	return false, nil
}
