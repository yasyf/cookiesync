// Package auth owns everything key-shaped in the cookiesync daemon: the consent
// grants store, the epoch-based key-cache handle, the Touch ID prompt gate, the
// release singleflight, the routed-consent nonce machinery, and every release
// path — the local batch release behind one Touch ID evaluation, the routed
// release that sends the user-presence gate to a live peer, and the bulk cache
// warming both share. The Broker is the only way a key is ever released or
// served: handlers in internal/daemon hold no cache or grants reference, so the
// package boundary enforces the one-key-path unification.
//
// Authorization is per requesting principal, never global cache warmth: a warm
// key is served silently only while the requestor holds a live grant for the
// browser, and a release grants its requestor every browser it covered.
package auth

import (
	"context"
	"errors"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/state"
	consentkit "github.com/yasyf/synckit/consent"
	"github.com/yasyf/synckit/presence"
)

// Mode selects whether a release derives the routed/local consent split or is
// pinned to a local terminus. A ModeLocal release walks the full ladder — hard
// consent route, local Touch ID, routed fallback — deriving the routed/local
// split once inside the flight (routesConsent), so every console release shares
// one routing rule and a mid-call presence flip cannot split one requestor's
// prompts across two flights. A ModeApprover release (an inbound
// request_consent) is the routed gate's terminus: it only ever releases
// locally, so the routed path is structurally unreachable and a 3+ mesh can
// never loop an approval back out; its pre-flight attended check folds into
// Key, failing Unavailable when no live session can be prompted.
type Mode string

const (
	// ModeLocal is the console release: prime, get_cookies, and extract alike.
	ModeLocal Mode = "local"
	// ModeApprover is the inbound request_consent release.
	ModeApprover Mode = "approver"
)

// Surface identifies which presence gate a release flight actually used: none
// (served from a warm cache inside a live grant), a local Touch ID evaluation,
// or a routed peer approval. A caller that sequences multiple releases keys its
// loop off each flight's actual surface — never a call-start routing snapshot,
// which a mid-call presence flip could stale out into a second sheet or a
// surprise route.
type Surface int

const (
	// SurfaceNone means no consent gate fired: the key came from a warm cache
	// inside a live grant, or the release failed before any gate.
	SurfaceNone Surface = iota
	// SurfaceLocal means a local Touch ID evaluation fired.
	SurfaceLocal
	// SurfaceRouted means the gate was routed to a peer approval.
	SurfaceRouted
)

// Budget bounds how many prompt flights a LocalKeys sweep may lead. It replaces
// the two divergent prompt-stop flag patterns the daemon's all-mode paths grew.
type Budget int

const (
	// OneFlight is the data-read budget: at most one release flight for the
	// whole sweep, whatever surface it used — anything still cold after it is
	// skipped.
	OneFlight Budget = iota
	// PrimeAll is the auth budget: a local Touch ID evaluation covers the whole
	// batch and stops the sweep, but a routed release gates one browser, so each
	// remaining cold browser leads its own routed flight.
	PrimeAll
)

// Req names one key request: the principal it acts for, the browser and profile
// whose Safe Storage key it wants, the Touch ID prompt reason, the release mode,
// and, for a cross-host bridge, the originating host named in the consent prompt.
type Req struct {
	Requestor string
	Browser   string
	Profile   string
	Reason    string
	Mode      Mode
	Origin    string
}

// Outcome is one local endpoint's result from a LocalKeys sweep. Under
// OneFlight there is one Outcome per tracked local endpoint, carrying the warm
// or released Key, the Err that left it cold, or Skipped when the budget was
// already spent. Under PrimeAll there is one Outcome per distinct local browser
// (keyed by its first tracked profile) and Warm lists the browser's tracked
// endpoint ids verified warm after the sweep — the verification rescan that
// fails the sweep closed when a demote raced every release.
type Outcome struct {
	Browser  string
	Profile  string
	Endpoint string
	Key      cookie.AesKey
	Err      error
	Skipped  bool
	Warm     []string
}

// Status is the key state auth_status reports for one endpoint: whether its key
// is warm in the cache, whether the cache is degraded to process memory, and
// whether the daemon user's keybag is unavailable.
type Status struct {
	Authenticated bool
	Degraded      bool
	KeybagLocked  bool
}

// approverUnavailableError marks an approver-side failure — a flaky presence
// probe or a broken initial cache read — as retryable by another mesh host.
type approverUnavailableError struct {
	err error
}

func (e *approverUnavailableError) Error() string { return e.err.Error() }
func (e *approverUnavailableError) Unwrap() error { return e.err }

// Classify maps a release error to a verdict: a locked keybag or an approver's
// failed probe/broken cache is Unavailable, a declined prompt is Denied, and
// everything else delegates to consentkit.Classify (fail-closed AuthRequired →
// Unavailable, routed Denied → Denied, else Fatal). The keybag check runs
// first, so a ConsentError wrapping ErrKeybagLocked is retryable, never a
// denial.
func Classify(err error) consentkit.Verdict {
	if err == nil {
		return consentkit.VerdictOK
	}
	if errors.Is(err, cookie.ErrKeybagLocked) {
		return consentkit.VerdictUnavailable
	}
	var unavailErr *approverUnavailableError
	if errors.As(err, &unavailErr) {
		return consentkit.VerdictUnavailable
	}
	var declined *cookie.ConsentError
	if errors.As(err, &declined) {
		return consentkit.VerdictDenied
	}
	return consentkit.Classify(err)
}

// ClassifyBridgeApproval maps a bridge-approval error to a verdict, differing
// from Classify only for a missing bridge vault: Unavailable (so routed consent
// advances to another approver) rather than Denied (which ends the loop).
func ClassifyBridgeApproval(err error) consentkit.Verdict {
	if errors.Is(err, cookie.ErrBridgeVaultMissing) {
		return consentkit.VerdictUnavailable
	}
	return Classify(err)
}

// Cache is the slice of the key cache the broker owns: the warmth read, the put
// a release seeds, and the degradation state auth_status surfaces. Defined
// here, where it is consumed; *cache.KeyCache satisfies it.
type Cache interface {
	// Get returns the cached key for endpointID, reporting ok=false on a miss.
	Get(ctx context.Context, endpointID string) (key []byte, ok bool, err error)
	// Put wraps key and records it under endpointID with the given TTL,
	// reporting whether it published under a degraded (process-memory) epoch —
	// the outcome grant windows derive from.
	Put(ctx context.Context, endpointID string, key []byte, ttl time.Duration) (degraded bool, err error)
	// Degraded reports whether cached keys are identity-wrapped in process
	// memory because the Secure Enclave refused its per-boot key.
	Degraded() bool
}

// StateLoader loads the cookiesync state the release paths derive endpoints,
// consent routes, and the auth TTL from. Injected so the broker runs against a
// fixture state.
type StateLoader interface {
	Load(ctx context.Context) (*state.State, error)
}

// SSHRunner runs a remote command over ssh and returns its stdout — the
// boundary the routed-consent handshake and the peer liveness probe cross.
type SSHRunner interface {
	Run(ctx context.Context, target, remoteCmd string, stdin []byte) (string, error)
}

// Probe reads this host's console GUI session. It is injected so the presence
// logic runs in tests against synthetic snapshots without touching macOS.
type Probe func(ctx context.Context) (presence.SessionSnapshot, error)

// meshSelf resolves this host's ssh target from the shared synckit mesh. Every
// cache key and consent-endpoint binding keys on it, never on this host's
// written-through self_target mirror.
func meshSelf(ctx context.Context) (string, error) {
	self, _, err := mesh.Resolve(ctx)
	if err != nil {
		return "", err
	}
	return self, nil
}

// endpointID is an endpoint's stable identity, host:browser:profile — the cache
// key and the routed-consent endpoint id.
func endpointID(host, browser, profile string) string {
	return string(state.Endpoint{Host: host, Browser: browser, Profile: profile}.ID())
}
