// Package cache holds a short-TTL, Secure-Enclave-wrapped cache for derived AES
// keys. The sync daemon derives a browser's Safe Storage key behind one Touch ID
// tap, then reuses it for a brief window so a burst of operations needs only a
// single prompt. The plaintext key lives in process memory for that window, but
// the at-rest cache bytes are Secure-Enclave-wrapped: a leaked blob or core dump
// is useless off-box, since only the live per-boot Enclave key can unwrap it.
//
// SecureEnclaveWrapper drives the installed, Developer-ID-signed
// cookiesync-keyhelper.app (cache-newkey / cache-wrap / cache-unwrap /
// cache-dropkey) through the helper bridge. A missing helper fails closed. When
// the Enclave refuses the per-boot key because no user is present (locked screen,
// screen-sharing session), OpenWrapper degrades to an in-memory wrapper instead of
// killing the daemon; see ErrSEPresenceUnavailable. The degradation self-heals:
// every KeyCache.Put re-probes cache-newkey until the keybag unlocks, then swaps to
// the real Enclave wrapper and evicts every identity-wrapped entry so cached keys
// re-prime Enclave-wrapped. Tests inject a Wrapper double and a clock, so the cache
// logic is exercised without any macOS API.
package cache

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/yasyf/cookiesync/internal/helper"
)

// ErrSEPresenceUnavailable reports that the Secure Enclave refused the per-boot key
// because the data-protection keybag is locked (screen locked / no user present).
// OpenWrapper returns it alongside a degraded in-memory wrapper: callers log the
// degradation and proceed, or fail as usual on any other error.
var ErrSEPresenceUnavailable = errors.New("secure-enclave presence unavailable")

// Wrapper wraps and unwraps key bytes so the at-rest cache value is opaque off-box.
type Wrapper interface {
	// Wrap returns an opaque blob that only Unwrap can reverse.
	Wrap(ctx context.Context, plaintext []byte) ([]byte, error)
	// Unwrap recovers the plaintext from a blob produced by Wrap.
	Unwrap(ctx context.Context, blob []byte) ([]byte, error)
}

// KeyWrapper is what OpenWrapper returns: a Wrapper plus Close, which drops the
// key material backing the wrapped blobs.
type KeyWrapper interface {
	Wrapper
	// Close drops whatever backs the wrapped blobs, making them unrecoverable.
	Close(ctx context.Context) error
}

// SecureEnclaveWrapper wraps key bytes against a per-boot ephemeral Secure-Enclave
// P-256 key. The Enclave key is created in Open (one random label per process) and
// destroyed in Close, so wrapped blobs are unrecoverable after the daemon exits or
// the machine reboots.
type SecureEnclaveWrapper struct {
	helper helper.Bridge
	label  string
}

// newLabel mints a fresh per-process Enclave key label: 8 random bytes hex-encoded
// (mirrors the Python secrets.token_hex(8)).
func newLabel() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate cache label: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// OpenWrapper creates the per-boot Secure-Enclave key (via cache-newkey under a
// fresh random label) through bridge and returns a wrapper bound to it. The caller
// must Close the wrapper to drop the Enclave key. bridge's zero value resolves the
// installed signed helper, failing closed if absent.
//
// When the keybag is unavailable (helper exit 3: screen locked, no user present),
// OpenWrapper returns a degraded wrapper together with an error matching
// ErrSEPresenceUnavailable, so the caller can warn and proceed with cached keys
// held only in process memory. The degraded wrapper heals itself: each KeyCache.Put
// re-probes cache-newkey and swaps to the Enclave once the keybag unlocks. Any
// other non-zero exit fails with the helper's stderr in the error.
func OpenWrapper(ctx context.Context, bridge helper.Bridge) (KeyWrapper, error) {
	label, err := newLabel()
	if err != nil {
		return nil, err
	}
	result, err := bridge.CacheNewkey(ctx, label)
	if err != nil {
		return nil, err
	}
	switch result.Code {
	case 0:
		return &SecureEnclaveWrapper{helper: bridge, label: label}, nil
	case helper.CodePresenceUnavailable:
		return &healingWrapper{bridge: bridge, label: label}, fmt.Errorf("cache-newkey exited %d (%s): %w",
			result.Code, bytes.TrimSpace(result.Stderr), ErrSEPresenceUnavailable)
	default:
		return nil, fmt.Errorf("cache-newkey exited %d (no Secure Enclave or keygen refused): %s",
			result.Code, bytes.TrimSpace(result.Stderr))
	}
}

// Label is the per-boot Enclave key label this wrapper drives.
func (w *SecureEnclaveWrapper) Label() string { return w.label }

// Wrap ECIES-encrypts plaintext against the Enclave key and returns the opaque blob.
func (w *SecureEnclaveWrapper) Wrap(ctx context.Context, plaintext []byte) ([]byte, error) {
	result, err := w.helper.CacheWrap(ctx, w.label, plaintext)
	if err != nil {
		return nil, err
	}
	if result.Code != 0 {
		return nil, fmt.Errorf("cache-wrap exited %d (key missing or encrypt failed): %s",
			result.Code, bytes.TrimSpace(result.Stderr))
	}
	return result.Stdout, nil
}

// Unwrap ECIES-decrypts blob with the Enclave key and returns the plaintext.
func (w *SecureEnclaveWrapper) Unwrap(ctx context.Context, blob []byte) ([]byte, error) {
	result, err := w.helper.CacheUnwrap(ctx, w.label, blob)
	if err != nil {
		return nil, err
	}
	if result.Code != 0 {
		return nil, fmt.Errorf("cache-unwrap exited %d (key missing or decrypt failed): %s",
			result.Code, bytes.TrimSpace(result.Stderr))
	}
	return result.Stdout, nil
}

// Close drops the per-boot Enclave key via cache-dropkey. It is idempotent: the
// helper exits 0 even when the key is already gone.
func (w *SecureEnclaveWrapper) Close(ctx context.Context) error {
	if _, err := w.helper.CacheDropkey(ctx, w.label); err != nil {
		return err
	}
	return nil
}

// memoryWrapper is the degraded inner of a healingWrapper: identity Wrap/Unwrap over
// copies, so cached keys live only in this process's memory — nothing ever touches
// the Enclave, the keychain, or disk — and Close has nothing to drop.
type memoryWrapper struct{}

func (memoryWrapper) Wrap(_ context.Context, plaintext []byte) ([]byte, error) {
	return bytes.Clone(plaintext), nil
}

func (memoryWrapper) Unwrap(_ context.Context, blob []byte) ([]byte, error) {
	return bytes.Clone(blob), nil
}

func (memoryWrapper) Close(context.Context) error { return nil }

// healingWrapper is the ErrSEPresenceUnavailable fallback: it starts over the
// identity memoryWrapper and swaps — permanently and at most once — to the real
// SecureEnclaveWrapper the first time a heal re-probe finds the keybag unlocked.
// KeyCache drives heal from Put and evicts every entry on the swap, so no
// identity-wrapped blob outlives the degradation.
type healingWrapper struct {
	bridge helper.Bridge
	label  string

	mu sync.Mutex
	se *SecureEnclaveWrapper
}

// current is the wrapper blobs are wrapped and unwrapped with right now: the
// Enclave wrapper once healed, the identity memoryWrapper while degraded.
func (w *healingWrapper) current() Wrapper {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.se != nil {
		return w.se
	}
	return memoryWrapper{}
}

func (w *healingWrapper) degraded() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.se == nil
}

// heal re-probes cache-newkey while degraded, returning the wrapper to wrap with
// and whether this call performed the memory-to-Enclave swap. A probe exit 3 stays
// degraded silently; any other non-zero exit fails the caller's Put loudly.
func (w *healingWrapper) heal(ctx context.Context) (Wrapper, bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.se != nil {
		return w.se, false, nil
	}
	result, err := w.bridge.CacheNewkey(ctx, w.label)
	if err != nil {
		return nil, false, err
	}
	switch result.Code {
	case 0:
		w.se = &SecureEnclaveWrapper{helper: w.bridge, label: w.label}
		return w.se, true, nil
	case helper.CodePresenceUnavailable:
		return memoryWrapper{}, false, nil
	default:
		return nil, false, fmt.Errorf("cache-newkey re-probe exited %d (no Secure Enclave or keygen refused): %s",
			result.Code, bytes.TrimSpace(result.Stderr))
	}
}

func (w *healingWrapper) Wrap(ctx context.Context, plaintext []byte) ([]byte, error) {
	return w.current().Wrap(ctx, plaintext)
}

func (w *healingWrapper) Unwrap(ctx context.Context, blob []byte) ([]byte, error) {
	return w.current().Unwrap(ctx, blob)
}

func (w *healingWrapper) Close(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.se == nil {
		return nil
	}
	return w.se.Close(ctx)
}

// entry is one cached key: the wrapped blob, the wrapper that produced it, and its
// absolute expiry.
type entry struct {
	blob      []byte
	wrapper   Wrapper
	expiresAt time.Time
}

// KeyCache is a short-TTL cache of derived AES keys, each stored only as a wrapped
// blob. Put wraps a key and records its expiry; Get unwraps transiently and
// returns a miss once the entry is expired or evicted. The plaintext is never
// persisted to disk and never logged. Eviction is lazy — there is no background
// goroutine — so an expired entry is dropped only when next requested or evicted
// explicitly. The clock is injectable for tests.
//
// Over a degraded healingWrapper, each Put first re-probes the Enclave: the Put
// that heals evicts every identity-wrapped entry, so cached keys re-prime
// Enclave-wrapped, and Degraded flips false.
type KeyCache struct {
	wrapper Wrapper
	healer  *healingWrapper
	now     func() time.Time

	mu      sync.Mutex
	entries map[string]entry
}

// NewKeyCache builds a cache over wrapper, using time.Now as the clock.
func NewKeyCache(wrapper Wrapper) *KeyCache {
	return NewKeyCacheWithClock(wrapper, time.Now)
}

// NewKeyCacheWithClock builds a cache over wrapper with an injected clock, for tests.
func NewKeyCacheWithClock(wrapper Wrapper, now func() time.Time) *KeyCache {
	healer, _ := wrapper.(*healingWrapper)
	return &KeyCache{wrapper: wrapper, healer: healer, now: now, entries: make(map[string]entry)}
}

// Degraded reports whether cached keys are currently identity-wrapped in process
// memory because the Secure Enclave refused its per-boot key at open. It flips
// false permanently once a Put heals the wrapper.
func (c *KeyCache) Degraded() bool {
	return c.healer != nil && c.healer.degraded()
}

// inner is the wrapper entries must have been wrapped with to be served.
func (c *KeyCache) inner() Wrapper {
	if c.healer == nil {
		return c.wrapper
	}
	return c.healer.current()
}

// heal re-probes a degraded healer and evicts every entry on the swap; with no
// healer it hands back the cache's own wrapper untouched.
func (c *KeyCache) heal(ctx context.Context) (Wrapper, error) {
	if c.healer == nil {
		return c.wrapper, nil
	}
	inner, healed, err := c.healer.heal(ctx)
	if err != nil {
		return nil, err
	}
	if healed {
		c.EvictAll()
	}
	return inner, nil
}

// Put wraps key and records it under endpointID with the given TTL, overwriting
// any existing entry.
func (c *KeyCache) Put(ctx context.Context, endpointID string, key []byte, ttl time.Duration) error {
	for {
		inner, err := c.heal(ctx)
		if err != nil {
			return err
		}
		blob, err := inner.Wrap(ctx, key)
		if err != nil {
			return err
		}
		c.mu.Lock()
		if inner == c.inner() {
			c.entries[endpointID] = entry{blob: blob, wrapper: inner, expiresAt: c.now().Add(ttl)}
			c.mu.Unlock()
			return nil
		}
		// A concurrent Put healed the wrapper mid-wrap; re-wrap with the Enclave so
		// no identity blob outlives the swap.
		c.mu.Unlock()
	}
}

// Get returns the cached key for endpointID, unwrapping it transiently. It returns
// (nil, false, nil) on a miss: no entry, an expired entry (which it evicts), or an
// entry wrapped before a heal swap (which the healing Put's eviction drops).
func (c *KeyCache) Get(ctx context.Context, endpointID string) ([]byte, bool, error) {
	c.mu.Lock()
	e, ok := c.entries[endpointID]
	if !ok {
		c.mu.Unlock()
		return nil, false, nil
	}
	if !c.now().Before(e.expiresAt) {
		delete(c.entries, endpointID)
		c.mu.Unlock()
		return nil, false, nil
	}
	c.mu.Unlock()

	if e.wrapper != c.inner() {
		return nil, false, nil
	}
	key, err := e.wrapper.Unwrap(ctx, e.blob)
	if err != nil {
		return nil, false, err
	}
	return key, true, nil
}

// Evict drops the entry for endpointID, if any.
func (c *KeyCache) Evict(endpointID string) {
	c.mu.Lock()
	delete(c.entries, endpointID)
	c.mu.Unlock()
}

// EvictAll drops every cached entry.
func (c *KeyCache) EvictAll() {
	c.mu.Lock()
	clear(c.entries)
	c.mu.Unlock()
}
