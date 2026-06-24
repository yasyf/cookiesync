// Package engine is the cookiesync sync engine: the value-union converge pass, the
// uniform cookie Source seam (local and ssh-backed peer), the anti-echo recorder, and
// the [converge.Driver] that drives the union over synckit's generic
// convergent-reconcile orchestration.
//
// A converge gathers the decrypted cookies of an endpoint and every tracked peer
// endpoint through one Source seam, merges them with the pure union newest-wins rule
// (cookie.Merge), and writes the merged set back to any endpoint whose rows differ —
// preserving each winner's last_update_utc and recording the applied anti-echo digest
// before the write, so the induced filesystem event is recognized as the daemon's own
// echo. Cookie last_update_utc is absolute Chrome time and host-independent, so the
// raw newest-wins comparison converges across NTP-synced machines with no clock-skew
// correction.
//
// Every collaborator — the key cache, the cookie sources, the anti-echo recorder, the
// clock — is injected, so the whole pass runs in unit tests against fakes without ssh,
// a real cookie store, or any macOS API.
package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
)

// ErrNeedsAuth reports that the local key cache holds no key for an endpoint's browser
// and a prompt is required first. Converge never prompts — the caller obtains consent
// and seeds the cache, then retries.
var ErrNeedsAuth = errors.New("no cached key for endpoint; obtain consent before converging")

// Extracted is a source's decrypted cookies for one browser profile.
type Extracted struct {
	Cookies []cookie.Cookie
}

// Source is one endpoint's cookie store, reached the same way whether it is local or a
// peer. Both the in-process local source and the ssh-backed peer satisfy this seam:
// Extract returns the decrypted cookies and Apply writes a merged set back. The Safe
// Storage key never crosses this boundary — the source decrypts and re-encrypts in its
// own session. Defined here, where the converge pass consumes it.
type Source interface {
	// Extract returns the decrypted cookies for browser/profile.
	Extract(ctx context.Context, browser, profile string) (Extracted, error)
	// Apply writes cookies back to browser/profile, returning the number of rows
	// written (-1 on a soft-busy locked store).
	Apply(ctx context.Context, browser, profile string, cookies []cookie.Cookie) (int, error)
}

// KeyCache is the short-TTL cache the local source reads the Safe Storage key from. It
// is the slice of the cache package the engine needs, defined here where it is used.
type KeyCache interface {
	// Get returns the cached key for endpointID, reporting ok=false on a miss.
	Get(ctx context.Context, endpointID string) (key []byte, ok bool, err error)
}

// CachedKeySource is the local host's Source, decrypting and re-encrypting with the
// cached Safe Storage key — never the consent gate, so the merge pass never prompts. A
// cold cache surfaces as ErrNeedsAuth.
type CachedKeySource struct {
	cache      KeyCache
	selfTarget string
}

// NewCachedKeySource builds the local source over cache, keyed by this host's self
// target so each browser profile resolves to its own cache entry.
func NewCachedKeySource(cache KeyCache, selfTarget string) CachedKeySource {
	return CachedKeySource{cache: cache, selfTarget: selfTarget}
}

func (s CachedKeySource) keyFor(ctx context.Context, browser, profile string) (cookie.AesKey, error) {
	id := string(state.Endpoint{Host: s.selfTarget, Browser: browser, Profile: profile}.ID())
	key, ok, err := s.cache.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: %s; run cookiesync auth", ErrNeedsAuth, id)
	}
	return cookie.AesKey(key), nil
}

// Extract reads every row of browser/profile off a private store copy and decrypts it
// with the cached key, dropping v20 app-bound and otherwise-undecryptable rows. A cold
// cache returns ErrNeedsAuth.
func (s CachedKeySource) Extract(ctx context.Context, browser, profile string) (Extracted, error) {
	key, err := s.keyFor(ctx, browser, profile)
	if err != nil {
		return Extracted{}, err
	}
	b, err := cookie.Lookup(cookie.BrowserName(browser))
	if err != nil {
		return Extracted{}, err
	}
	rows, err := cookie.Read(ctx, b, profile)
	if err != nil {
		return Extracted{}, err
	}
	cookies := make([]cookie.Cookie, 0, len(rows))
	for _, row := range rows {
		if c, ok := cookie.DecryptRow(row, key); ok {
			cookies = append(cookies, c)
		}
	}
	return Extracted{Cookies: cookies}, nil
}

// Apply re-encrypts cookies into browser/profile's live store with the cached key.
func (s CachedKeySource) Apply(ctx context.Context, browser, profile string, cookies []cookie.Cookie) (int, error) {
	key, err := s.keyFor(ctx, browser, profile)
	if err != nil {
		return 0, err
	}
	b, err := cookie.Lookup(cookie.BrowserName(browser))
	if err != nil {
		return 0, err
	}
	return cookie.Apply(ctx, cookies, b, profile, key)
}
