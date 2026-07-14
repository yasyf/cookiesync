// Package cache holds a short-TTL, Secure-Enclave-wrapped cache for derived AES
// keys. The sync daemon derives a browser's Safe Storage key behind one Touch ID
// tap, then reuses it for a brief window so a burst of operations needs only a
// single prompt. The plaintext key lives in process memory for that window, but
// the at-rest cache bytes are Secure-Enclave-wrapped: a leaked blob or core dump
// is useless off-box, since only the live per-boot Enclave key can unwrap it.
//
// The cache drives the installed, Developer-ID-signed cookiesync-keyhelper.app
// (cache-newkey / cache-wrap / cache-unwrap / cache-dropkey) through the Helper
// seam; a missing helper fails closed. Its wrap state moves between the ENCLAVE
// and MEMORY epochs, with CLOSED terminal: whenever the Enclave refuses the
// per-boot key because no user is present (locked screen, screen-sharing
// session) — at Open or on any later wrap or unwrap — the cache demotes itself
// to holding keys in process memory, and each Put re-probes cache-newkey until
// the keybag unlocks, healing back to Enclave wrapping. Every transition
// installs a freshly heap-allocated epoch and each entry remembers the epoch it
// was wrapped under, so pointer identity is the generation test: no two eras
// ever compare equal, even when both are MEMORY. Presence refusal is a
// cache-internal event — callers only ever see a miss and fall through to a
// fresh release. Tests inject a Helper double and a clock, so the cache logic
// is exercised without any macOS API.
package cache

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yasyf/cookiesync/internal/helper"
)

// DegradedTTL caps the lifetime of every entry published under a MEMORY epoch:
// a RAM-only key never outlives this window, whatever TTL the caller asked for.
const DegradedTTL = 5 * time.Minute

// closeLockPoll is the interval Close retries healMu at while bounded by its
// context.
const closeLockPoll = 10 * time.Millisecond

// ErrClosed reports a Put against a closed cache: Close is terminal, so a caller
// holding a closed cache is shutting down and must not mint new entries.
var ErrClosed = errors.New("key cache closed")

// Helper is the slice of the signed key-helper bridge the cache drives: the
// per-boot Enclave key lifecycle and the wrap/unwrap round-trip. helper.Bridge
// satisfies it; tests inject an in-process double.
type Helper interface {
	CacheNewkey(ctx context.Context, label string) (helper.Result, error)
	CacheWrap(ctx context.Context, label string, plaintext []byte) (helper.Result, error)
	CacheUnwrap(ctx context.Context, label string, blob []byte) (helper.Result, error)
	CacheDropkey(ctx context.Context, label string) (helper.Result, error)
}

// stateKind names an epoch's wrap state.
type stateKind int

const (
	stateEnclave stateKind = iota // blobs ECIES-wrapped against the per-boot Enclave key
	stateMemory                   // blobs identity-wrapped in process memory (keybag refused presence)
	stateClosed                   // terminal: entries evicted, the Enclave key dropped
)

// epoch is one era of the cache's wrap state. Every transition allocates a fresh
// epoch on the heap, so pointer identity distinguishes eras that would compare
// equal by value.
type epoch struct {
	kind stateKind
}

// entry is one cached key: the wrapped blob, the epoch that produced it, and its
// absolute expiry.
type entry struct {
	blob      []byte
	ep        *epoch
	expiresAt time.Time
}

// KeyCache is a short-TTL cache of derived AES keys, each stored only as a
// wrapped blob. Put wraps a key and records its expiry; Get unwraps transiently
// and returns a miss once the entry is expired, evicted, or from a stale epoch.
// The plaintext is never persisted to disk and never logged. Eviction is lazy —
// there is no background goroutine — so a dead entry is dropped only when next
// requested. The clock is injectable for tests.
type KeyCache struct {
	helper Helper
	label  string
	now    func() time.Time

	state atomic.Pointer[epoch]

	// healMu serializes the writers heal and Close. Readers (Get, Degraded) and
	// demote never take it, so a heal parked in cache-newkey — a human-timescale
	// presence prompt — cannot stall them.
	healMu  sync.Mutex
	keyLive bool // an Enclave key exists under label; guarded by healMu after Open

	mu      sync.Mutex // guards entries; never held across a helper subprocess
	entries map[string]entry
}

// Open mints a fresh per-boot Enclave key label, provisions the key via
// cache-newkey through h, and returns the cache in the ENCLAVE state. When the
// keybag refuses presence (helper exit 3: screen locked, no user present) the
// cache opens degraded in the MEMORY state instead, healing on a later Put; any
// other non-zero exit fails closed with the helper's stderr. The caller must
// Close the cache to drop the Enclave key.
func Open(ctx context.Context, h Helper) (*KeyCache, error) {
	return open(ctx, h, time.Now)
}

func open(ctx context.Context, h Helper, now func() time.Time) (*KeyCache, error) {
	label, err := newLabel()
	if err != nil {
		return nil, err
	}
	c := &KeyCache{helper: h, label: label, now: now, entries: map[string]entry{}}
	result, err := h.CacheNewkey(ctx, label)
	if err != nil {
		return nil, err
	}
	switch result.Code {
	case 0:
		c.keyLive = true
		c.state.Store(&epoch{kind: stateEnclave})
	case helper.CodePresenceUnavailable:
		slog.WarnContext(ctx, "Secure Enclave presence unavailable — screen locked or no user present; caching keys in process memory until the keybag unlocks",
			"stderr", string(bytes.TrimSpace(result.Stderr)))
		c.state.Store(&epoch{kind: stateMemory})
	default:
		return nil, fmt.Errorf("cache-newkey exited %d (no Secure Enclave or keygen refused): %s",
			result.Code, bytes.TrimSpace(result.Stderr))
	}
	return c, nil
}

// Degraded reports whether cached keys are currently identity-wrapped in process
// memory because the Secure Enclave refused its per-boot key — at Open or on a
// later mid-life refusal. It flips back once a Put heals the cache.
func (c *KeyCache) Degraded() bool {
	return c.state.Load().kind == stateMemory
}

// Get returns the cached key for endpointID, unwrapping it transiently. It
// returns (nil, false, nil) on a miss: no entry, an expired entry, a stale-epoch
// entry (both evicted), or an entry whose unwrap the keybag refused — the
// refusal demotes the cache to MEMORY, evicts the dead entry, and reads as a
// miss so the caller falls through to a fresh release. An unwrap that completes
// after its epoch was retired mid-flight — by a demote, a heal, or Close — also
// reads as a miss whatever it returned: a stale success never resurrects a dead
// entry and a stale error never propagates raw (it reads ErrClosed once the
// cache is CLOSED). Any other unwrap failure is an error.
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

	if e.ep != c.state.Load() {
		c.evict(endpointID, e.ep)
		return nil, false, nil
	}
	key, refused, err := c.unwrap(ctx, e.ep, e.blob)
	if cur := c.state.Load(); cur != e.ep {
		c.evict(endpointID, e.ep)
		if err != nil && cur.kind == stateClosed {
			return nil, false, ErrClosed
		}
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if refused {
		c.demote(e.ep)
		c.evict(endpointID, e.ep)
		return nil, false, nil
	}
	return key, true, nil
}

// Put wraps key and records it under endpointID, overwriting any existing
// entry, and reports whether it published under a MEMORY epoch — the outcome a
// caller derives its grant window from, never a pre-Put probe of a state that
// can demote or heal mid-call. An entry published under MEMORY has its TTL
// capped at DegradedTTL. Over a MEMORY epoch Put re-probes the Enclave under
// healMu at most once per call, success or refusal — under presence flapping a
// post-heal wrap refusal demotes and publishes in memory instead of re-probing
// — and a wrap the keybag refuses demotes the failing epoch and retries, so
// presence refusal can never fail a Put: a routed approval always caches. A
// wrap that completes after its epoch was retired is discarded — success,
// refusal, and error alike — and the loop re-resolves the current epoch and
// re-wraps under it; the entry publishes only while its captured epoch is still
// current. Returns ErrClosed after Close.
func (c *KeyCache) Put(ctx context.Context, endpointID string, key []byte, ttl time.Duration) (degraded bool, err error) {
	healed := false
	for {
		ep := c.state.Load()
		switch ep.kind {
		case stateClosed:
			return false, ErrClosed
		case stateMemory:
			if !healed {
				healed = true
				cur, err := c.heal(ctx)
				if err != nil {
					return false, err
				}
				if cur.kind == stateClosed {
					return false, ErrClosed
				}
				ep = cur
			}
		}
		blob, refused, err := c.wrap(ctx, ep, key)
		if cur := c.state.Load(); cur != ep {
			if cur.kind == stateClosed {
				return false, ErrClosed
			}
			continue
		}
		if err != nil {
			return false, err
		}
		if refused {
			c.demote(ep)
			continue
		}
		entryTTL := ttl
		if ep.kind == stateMemory && entryTTL > DegradedTTL {
			entryTTL = DegradedTTL
		}
		c.mu.Lock()
		if c.state.Load() == ep {
			c.entries[endpointID] = entry{blob: blob, ep: ep, expiresAt: c.now().Add(entryTTL)}
			c.mu.Unlock()
			return ep.kind == stateMemory, nil
		}
		c.mu.Unlock()
	}
}

// Close is terminal: it installs the CLOSED epoch and evicts every entry in one
// atomic step, then drops the per-boot Enclave key — once, and only when one was
// ever provisioned. After Close every Get misses, every Put returns ErrClosed,
// and a repeat Close is a no-op: the key is per-boot, so a failed drop is
// surfaced but never retried. The healMu acquisition is bounded by ctx — a heal
// parked in its presence prompt cannot hold shutdown past its deadline; Close
// then fails with the ctx error and performs no transition, and the per-boot
// key dies with the process anyway.
func (c *KeyCache) Close(ctx context.Context) error {
	if err := c.lockHealBounded(ctx); err != nil {
		return fmt.Errorf("close key cache: %w", err)
	}
	defer c.healMu.Unlock()
	if c.state.Load().kind == stateClosed {
		return nil
	}
	c.mu.Lock()
	c.state.Store(&epoch{kind: stateClosed})
	clear(c.entries)
	c.mu.Unlock()
	if !c.keyLive {
		return nil
	}
	result, err := c.helper.CacheDropkey(ctx, c.label)
	if err != nil {
		return err
	}
	if result.Code != 0 {
		return fmt.Errorf("cache-dropkey exited %d (key still live): %s",
			result.Code, bytes.TrimSpace(result.Stderr))
	}
	return nil
}

// heal re-probes cache-newkey under healMu while the cache sits in a MEMORY
// epoch, installing a fresh ENCLAVE epoch on success and — atomically with the
// install — evicting every entry from another epoch, so no identity-wrapped
// blob outlives the swap while an entry published under the new epoch is
// spared. A keybag still refusing presence leaves the MEMORY epoch in place
// silently; any other non-zero exit fails the caller's Put loudly. Returns the
// epoch current once it is done.
func (c *KeyCache) heal(ctx context.Context) (*epoch, error) {
	c.healMu.Lock()
	defer c.healMu.Unlock()
	cur := c.state.Load()
	if cur.kind != stateMemory {
		return cur, nil
	}
	result, err := c.helper.CacheNewkey(ctx, c.label)
	if err != nil {
		return nil, err
	}
	switch result.Code {
	case 0:
		next := &epoch{kind: stateEnclave}
		c.keyLive = true
		c.mu.Lock()
		c.state.Store(next)
		for id, e := range c.entries {
			if e.ep != next {
				delete(c.entries, id)
			}
		}
		c.mu.Unlock()
		slog.InfoContext(ctx, "Secure Enclave keybag unlocked; key cache healed to Enclave wrapping")
		return next, nil
	case helper.CodePresenceUnavailable:
		return cur, nil
	default:
		return nil, fmt.Errorf("cache-newkey re-probe exited %d (no Secure Enclave or keygen refused): %s",
			result.Code, bytes.TrimSpace(result.Stderr))
	}
}

// lockHealBounded acquires healMu, retrying every closeLockPoll until ctx
// expires; it never parks behind a heal past the caller's deadline.
func (c *KeyCache) lockHealBounded(ctx context.Context) error {
	for {
		if c.healMu.TryLock() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(closeLockPoll):
		}
	}
}

// demote swaps failing for a fresh MEMORY epoch. It CASes rather than stores, so
// a slow refusal racing a newer heal or Close loses: only the epoch that
// observed the refusal is ever replaced. The CAS runs under c.mu, serializing it
// with Put's check-and-publish so a demote never lands between an epoch check
// and its map write. It never takes healMu, so a demote landing during a parked
// heal probe cannot stall behind it.
func (c *KeyCache) demote(failing *epoch) {
	c.mu.Lock()
	swapped := c.state.CompareAndSwap(failing, &epoch{kind: stateMemory})
	c.mu.Unlock()
	if swapped {
		slog.Warn("Secure Enclave refused the per-boot key; key cache degraded to process memory until the keybag unlocks")
	}
}

// evict drops endpointID while it still holds an entry from ep, so a racing Put
// under a newer epoch is never clobbered.
func (c *KeyCache) evict(endpointID string, ep *epoch) {
	c.mu.Lock()
	if e, ok := c.entries[endpointID]; ok && e.ep == ep {
		delete(c.entries, endpointID)
	}
	c.mu.Unlock()
}

// wrap seals key for storage under ep: an identity copy in MEMORY, an ECIES blob
// from cache-wrap in ENCLAVE. refused reports a keybag presence refusal (helper
// exit 3); any other non-zero exit is an error.
func (c *KeyCache) wrap(ctx context.Context, ep *epoch, key []byte) (blob []byte, refused bool, err error) {
	if ep.kind == stateMemory {
		return bytes.Clone(key), false, nil
	}
	result, err := c.helper.CacheWrap(ctx, c.label, key)
	if err != nil {
		return nil, false, err
	}
	switch result.Code {
	case 0:
		return result.Stdout, false, nil
	case helper.CodePresenceUnavailable:
		return nil, true, nil
	default:
		return nil, false, fmt.Errorf("cache-wrap exited %d (key missing or encrypt failed): %s",
			result.Code, bytes.TrimSpace(result.Stderr))
	}
}

// unwrap recovers the key from blob under ep, mirroring wrap's refusal contract.
func (c *KeyCache) unwrap(ctx context.Context, ep *epoch, blob []byte) (key []byte, refused bool, err error) {
	if ep.kind == stateMemory {
		return bytes.Clone(blob), false, nil
	}
	result, err := c.helper.CacheUnwrap(ctx, c.label, blob)
	if err != nil {
		return nil, false, err
	}
	switch result.Code {
	case 0:
		return result.Stdout, false, nil
	case helper.CodePresenceUnavailable:
		return nil, true, nil
	default:
		return nil, false, fmt.Errorf("cache-unwrap exited %d (key missing or decrypt failed): %s",
			result.Code, bytes.TrimSpace(result.Stderr))
	}
}

// newLabel mints a fresh per-process Enclave key label: 8 random bytes
// hex-encoded (mirrors the Python secrets.token_hex(8)).
func newLabel() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate cache label: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
