package engine

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
)

// testLockFor is a fresh per-test apply-lock seam over a private keyedLocks.
func testLockFor() func(string) *sync.Mutex {
	var locks keyedLocks
	return locks.lock
}

// fakeSource is an in-memory Source: it serves a fixed cookie set and records every
// Apply, so a test can assert what was written (or that nothing was) per endpoint.
type fakeSource struct {
	cookies []cookie.Cookie
	applies [][]cookie.Cookie
}

func (s *fakeSource) Extract(_ context.Context, _, _ string) (Extracted, error) {
	return Extracted{Cookies: append([]cookie.Cookie(nil), s.cookies...)}, nil
}

func (s *fakeSource) Apply(_ context.Context, _, _ string, cookies []cookie.Cookie) (int, error) {
	s.cookies = append([]cookie.Cookie(nil), cookies...)
	s.applies = append(s.applies, append([]cookie.Cookie(nil), cookies...))
	return len(cookies), nil
}

// warmCache is a KeyCache that reports every endpoint warm, returning a dummy key. The
// converge pass only checks warmth and passes the key through to the source, which is
// faked, so the bytes are irrelevant.
type warmCache struct {
	cold map[string]bool
}

func (c warmCache) Get(_ context.Context, endpointID string) ([]byte, bool, error) {
	if c.cold[endpointID] {
		return nil, false, nil
	}
	return []byte("0123456789abcdef"), true, nil
}

// countingRecorder records every (endpoint, digest) the converge pass applied, so the
// anti-echo assertions can check the digest was recorded before each write.
type countingRecorder struct {
	recorded []recorded
}

type recorded struct {
	endpoint string
	digest   cookie.Digest
}

func (r *countingRecorder) RecordApplied(endpointID string, digest cookie.Digest) {
	r.recorded = append(r.recorded, recorded{endpoint: endpointID, digest: digest})
}

func ck(host, name, value string, lastUpdate cookie.ChromeMicros) cookie.Cookie {
	return cookie.Cookie{
		HostKey:       cookie.HostKey(host),
		Name:          name,
		Value:         value,
		Path:          "/",
		LastUpdateUTC: lastUpdate,
		SameSite:      2,
	}
}

// TestConvergeValueUnionNewestWins proves a converge over a local endpoint and a peer
// endpoint merges to the union, newest-wins per logical key, and writes the merged set
// back to each endpoint whose rows differed — recording the anti-echo digest before
// each write.
func TestConvergeValueUnionNewestWins(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	peerHost := "you@desktop"

	// Local holds an old "sid" and a unique "local-only"; peer holds a newer "sid" and
	// a unique "peer-only". The union keeps the newer sid plus both uniques.
	local := &fakeSource{cookies: []cookie.Cookie{
		ck(".x.com", "sid", "old", 100),
		ck(".x.com", "localonly", "L", 50),
	}}
	peer := &fakeSource{cookies: []cookie.Cookie{
		ck(".x.com", "sid", "new", 200),
		ck(".x.com", "peeronly", "P", 60),
	}}

	rec := &countingRecorder{}
	deps := ConvergeDeps{
		SelfTarget:  self,
		Cache:       warmCache{},
		Recorder:    rec,
		LocalSource: local,
		SourceFor:   func(string) Source { return peer },
		LockFor:     testLockFor(),
	}

	anchor := state.Endpoint{Host: self, Browser: "chrome", Profile: "Default"}
	peerEP := state.Endpoint{Host: peerHost, Browser: "chrome", Profile: "Default"}

	merged, err := Converge(ctx, anchor, []state.Endpoint{peerEP}, "", deps)
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}

	wantValues := map[string]string{"sid": "new", "localonly": "L", "peeronly": "P"}
	if len(merged) != len(wantValues) {
		t.Fatalf("merged has %d cookies, want %d: %+v", len(merged), len(wantValues), merged)
	}
	for _, c := range merged {
		if wantValues[c.Name] != c.Value {
			t.Fatalf("merged %s = %q, want %q", c.Name, c.Value, wantValues[c.Name])
		}
	}

	// Both endpoints differed from the union, so both were written, each preceded by a
	// recorded digest equal to the merged set's logical digest.
	if len(local.applies) != 1 || len(peer.applies) != 1 {
		t.Fatalf("expected one write per endpoint, got local=%d peer=%d", len(local.applies), len(peer.applies))
	}
	wantDigest := cookie.LogicalDigest(merged)
	if len(rec.recorded) != 2 {
		t.Fatalf("expected 2 recorded digests (one per write), got %d", len(rec.recorded))
	}
	for _, r := range rec.recorded {
		if r.digest != wantDigest {
			t.Fatalf("recorded digest %s != merged digest %s", r.digest, wantDigest)
		}
	}
}

// TestConvergeIdempotentOnRerun proves a second converge over an already-converged
// group writes nothing and records nothing: the row sets already match the union, so
// apply_to is a no-op — the property the anti-echo relies on.
func TestConvergeIdempotentOnRerun(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	peerHost := "you@desktop"

	local := &fakeSource{cookies: []cookie.Cookie{ck(".x.com", "sid", "new", 200)}}
	peer := &fakeSource{cookies: []cookie.Cookie{ck(".x.com", "sid", "new", 200)}}
	rec := &countingRecorder{}
	deps := ConvergeDeps{
		SelfTarget:  self,
		Cache:       warmCache{},
		Recorder:    rec,
		LocalSource: local,
		SourceFor:   func(string) Source { return peer },
		LockFor:     testLockFor(),
	}
	anchor := state.Endpoint{Host: self, Browser: "chrome", Profile: "Default"}
	peerEP := state.Endpoint{Host: peerHost, Browser: "chrome", Profile: "Default"}

	if _, err := Converge(ctx, anchor, []state.Endpoint{peerEP}, "", deps); err != nil {
		t.Fatalf("first converge: %v", err)
	}
	if len(local.applies) != 0 || len(peer.applies) != 0 {
		t.Fatalf("already-equal endpoints should not be written: local=%d peer=%d", len(local.applies), len(peer.applies))
	}
	if len(rec.recorded) != 0 {
		t.Fatalf("no write means no recorded digest, got %d", len(rec.recorded))
	}
}

// TestConvergeAntiEchoSuppressesSelfWrite proves the recorded digest matches the
// digest a fresh fingerprint of the just-written store would produce: the converge
// records logical_digest(merged) before the write, and the store ends up holding
// exactly merged, so a watch loop fingerprinting it sees the same digest and suppresses
// the self-induced event.
func TestConvergeAntiEchoSuppressesSelfWrite(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"

	local := &fakeSource{cookies: []cookie.Cookie{ck(".x.com", "sid", "old", 100)}}
	peer := &fakeSource{cookies: []cookie.Cookie{ck(".x.com", "sid", "new", 200)}}
	rec := &countingRecorder{}
	deps := ConvergeDeps{
		SelfTarget:  self,
		Cache:       warmCache{},
		Recorder:    rec,
		LocalSource: local,
		SourceFor:   func(string) Source { return peer },
		LockFor:     testLockFor(),
	}
	anchor := state.Endpoint{Host: self, Browser: "chrome", Profile: "Default"}
	peerEP := state.Endpoint{Host: "you@desktop", Browser: "chrome", Profile: "Default"}

	merged, err := Converge(ctx, anchor, []state.Endpoint{peerEP}, "", deps)
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}

	// The recorded digest for the local endpoint must equal the digest of what the
	// store now holds (local.cookies after the write) — the anti-echo invariant.
	storeDigest := cookie.LogicalDigest(local.cookies)
	mergedDigest := cookie.LogicalDigest(merged)
	if storeDigest != mergedDigest {
		t.Fatalf("post-write store digest %s != merged digest %s", storeDigest, mergedDigest)
	}
	var localRecorded cookie.Digest
	for _, r := range rec.recorded {
		if r.endpoint == string(anchor.ID()) {
			localRecorded = r.digest
		}
	}
	if localRecorded != storeDigest {
		t.Fatalf("recorded digest %s != post-write store digest %s; echo would NOT be suppressed", localRecorded, storeDigest)
	}
}

// TestConvergeSkipsOriginHost proves an endpoint on the origin host is excluded from
// the union, so a sync is never echoed straight back to the host that triggered it.
func TestConvergeSkipsOriginHost(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	originHost := "trigger@host"

	local := &fakeSource{cookies: []cookie.Cookie{ck(".x.com", "sid", "local", 100)}}
	originSrc := &fakeSource{cookies: []cookie.Cookie{ck(".x.com", "sid", "fromorigin", 999)}}
	deps := ConvergeDeps{
		SelfTarget:  self,
		Cache:       warmCache{},
		Recorder:    &countingRecorder{},
		LocalSource: local,
		SourceFor:   func(string) Source { return originSrc },
		LockFor:     testLockFor(),
	}
	anchor := state.Endpoint{Host: self, Browser: "chrome", Profile: "Default"}
	originEP := state.Endpoint{Host: originHost, Browser: "chrome", Profile: "Default"}

	merged, err := Converge(ctx, anchor, []state.Endpoint{originEP}, originHost, deps)
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if len(originSrc.applies) != 0 {
		t.Fatalf("origin endpoint must not be written back")
	}
	for _, c := range merged {
		if c.Value == "fromorigin" {
			t.Fatalf("origin host's cookies leaked into the union: %+v", merged)
		}
	}
}

// TestConvergeSkipsColdSameHostPeer proves a cold same-host peer is skipped (its
// consent never ran) rather than failing the whole converge.
func TestConvergeSkipsColdSameHostPeer(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"

	local := &fakeSource{cookies: []cookie.Cookie{ck(".x.com", "sid", "v", 100)}}
	anchor := state.Endpoint{Host: self, Browser: "chrome", Profile: "Default"}
	coldPeer := state.Endpoint{Host: self, Browser: "arc", Profile: "Default"}

	deps := ConvergeDeps{
		SelfTarget:  self,
		Cache:       warmCache{cold: map[string]bool{string(coldPeer.ID()): true}},
		Recorder:    &countingRecorder{},
		LocalSource: local,
		SourceFor:   func(string) Source { t.Fatal("no ssh source for a same-host peer"); return nil },
		LockFor:     testLockFor(),
	}

	if _, err := Converge(ctx, anchor, []state.Endpoint{coldPeer}, "", deps); err != nil {
		t.Fatalf("Converge should skip the cold same-host peer, got %v", err)
	}
}

// TestConvergeColdAnchorNeedsAuth proves a cold anchor returns ErrNeedsAuth rather than
// prompting or writing.
func TestConvergeColdAnchorNeedsAuth(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	anchor := state.Endpoint{Host: self, Browser: "chrome", Profile: "Default"}
	deps := ConvergeDeps{
		SelfTarget:  self,
		Cache:       warmCache{cold: map[string]bool{string(anchor.ID()): true}},
		Recorder:    &countingRecorder{},
		LocalSource: &fakeSource{},
		SourceFor:   func(string) Source { return &fakeSource{} },
	}
	_, err := Converge(ctx, anchor, nil, "", deps)
	if err == nil {
		t.Fatalf("expected ErrNeedsAuth for a cold anchor")
	}
}

// TestConvergeLocksLocalWritesOnly proves a converge takes the per-endpoint apply lock
// for exactly the local endpoints it writes — the anchor and the same-host peer — and
// never for a remote peer, whose apply crosses ssh and must not run under a held lock.
// Every lock is released by the time Converge returns.
func TestConvergeLocksLocalWritesOnly(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"

	local := &fakeSource{cookies: []cookie.Cookie{ck(".x.com", "sid", "old", 100)}}
	peer := &fakeSource{cookies: []cookie.Cookie{ck(".x.com", "sid", "new", 200)}}

	var locks keyedLocks
	var acquired []string
	deps := ConvergeDeps{
		SelfTarget:  self,
		Cache:       warmCache{},
		Recorder:    &countingRecorder{},
		LocalSource: local,
		SourceFor:   func(string) Source { return peer },
		LockFor: func(endpointID string) *sync.Mutex {
			acquired = append(acquired, endpointID)
			return locks.lock(endpointID)
		},
	}
	anchor := state.Endpoint{Host: self, Browser: "chrome", Profile: "Default"}
	sameHost := state.Endpoint{Host: self, Browser: "arc", Profile: "Default"}
	remote := state.Endpoint{Host: "you@desktop", Browser: "chrome", Profile: "Default"}

	if _, err := Converge(ctx, anchor, []state.Endpoint{sameHost, remote}, "", deps); err != nil {
		t.Fatalf("Converge: %v", err)
	}
	want := []string{string(anchor.ID()), string(sameHost.ID())}
	if !slices.Equal(acquired, want) {
		t.Fatalf("apply locks acquired for %v, want exactly the local endpoints %v", acquired, want)
	}
	for _, id := range want {
		if !locks.locks[id].TryLock() {
			t.Fatalf("apply lock for %s still held after Converge", id)
		}
	}
}
