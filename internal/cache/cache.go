// Package cache holds a short-TTL, Secure-Enclave-wrapped cache for derived AES
// keys. The sync daemon derives a browser's Safe Storage key behind one Touch ID
// tap, then reuses it for a brief window so a burst of operations needs only a
// single prompt. The plaintext key lives in process memory for that window, but
// the at-rest cache bytes are Secure-Enclave-wrapped: a leaked blob or core dump
// is useless off-box, since only the live per-boot Enclave key can unwrap it.
//
// SecureEnclaveWrapper drives the installed, Developer-ID-signed
// cookiesync-keyhelper.app (cache-newkey / cache-wrap / cache-unwrap /
// cache-dropkey) through the helper bridge. A missing helper fails closed. Tests
// inject a Wrapper double and a clock, so the cache logic is exercised without any
// macOS API.
package cache

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/yasyf/cookiesync/internal/helper"
)

// Wrapper wraps and unwraps key bytes so the at-rest cache value is opaque off-box.
type Wrapper interface {
	// Wrap returns an opaque blob that only Unwrap can reverse.
	Wrap(ctx context.Context, plaintext []byte) ([]byte, error)
	// Unwrap recovers the plaintext from a blob produced by Wrap.
	Unwrap(ctx context.Context, blob []byte) ([]byte, error)
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
func OpenWrapper(ctx context.Context, bridge helper.Bridge) (*SecureEnclaveWrapper, error) {
	label, err := newLabel()
	if err != nil {
		return nil, err
	}
	result, err := bridge.CacheNewkey(ctx, label)
	if err != nil {
		return nil, err
	}
	if result.Code != 0 {
		return nil, fmt.Errorf("cache-newkey exited %d (no Secure Enclave or keygen refused)", result.Code)
	}
	return &SecureEnclaveWrapper{helper: bridge, label: label}, nil
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
		return nil, fmt.Errorf("cache-wrap exited %d (key missing or encrypt failed)", result.Code)
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
		return nil, fmt.Errorf("cache-unwrap exited %d (key missing or decrypt failed)", result.Code)
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

// entry is one cached key: the wrapped blob and its absolute expiry.
type entry struct {
	blob      []byte
	expiresAt time.Time
}

// KeyCache is a short-TTL cache of derived AES keys, each stored only as a wrapped
// blob. Put wraps a key and records its expiry; Get unwraps transiently and
// returns a miss once the entry is expired or evicted. The plaintext is never
// persisted to disk and never logged. Eviction is lazy — there is no background
// goroutine — so an expired entry is dropped only when next requested or evicted
// explicitly. The clock is injectable for tests.
type KeyCache struct {
	wrapper Wrapper
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
	return &KeyCache{wrapper: wrapper, now: now, entries: make(map[string]entry)}
}

// Put wraps key and records it under endpointID with the given TTL, overwriting
// any existing entry.
func (c *KeyCache) Put(ctx context.Context, endpointID string, key []byte, ttl time.Duration) error {
	blob, err := c.wrapper.Wrap(ctx, key)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.entries[endpointID] = entry{blob: blob, expiresAt: c.now().Add(ttl)}
	c.mu.Unlock()
	return nil
}

// Get returns the cached key for endpointID, unwrapping it transiently. It returns
// (nil, false, nil) on a miss: no entry, or an expired entry (which it evicts).
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

	key, err := c.wrapper.Unwrap(ctx, e.blob)
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
