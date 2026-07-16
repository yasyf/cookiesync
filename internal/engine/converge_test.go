package engine

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
)

const testFutureExpiry cookie.ChromeMicros = 20_000_000_000_000_000

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

// memBaselines is an in-memory BaselineStore, seedable and inspectable, counting saves
// so a test can assert the ledger is only persisted when it changed.
type memBaselines struct {
	baselines map[string]state.Baseline
	saves     int
}

func newMemBaselines() *memBaselines {
	return &memBaselines{baselines: map[string]state.Baseline{}}
}

func (b *memBaselines) Baselines(_ context.Context) (map[string]state.Baseline, error) {
	out := make(map[string]state.Baseline, len(b.baselines))
	for id, baseline := range b.baselines {
		out[id] = baseline
	}
	return out, nil
}

func (b *memBaselines) SaveBaselinesUnlocked(_ context.Context, baselines map[string]state.Baseline) error {
	b.baselines = baselines
	b.saves++
	return nil
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
		ExpiresUTC:    testFutureExpiry,
		LastUpdateUTC: lastUpdate,
		SameSite:      2,
	}
}

func TestConvergeFiltersUnsyncableRows(t *testing.T) {
	liveLocal := ck(".x.com", "local", "L", 100)
	livePeer := ck(".x.com", "peer", "P", 200)
	expired := ck(".x.com", "expired", "dead", 300)
	expired.ExpiresUTC = 1
	session := ck(".x.com", "session", "dead", 400)
	session.ExpiresUTC = 0

	tests := []struct {
		name        string
		local       []cookie.Cookie
		peer        []cookie.Cookie
		wantMerged  []cookie.Cookie
		wantApplies int
	}{
		{
			name:        "dead peer rows reach neither union nor apply payloads",
			local:       []cookie.Cookie{liveLocal},
			peer:        []cookie.Cookie{livePeer, expired, session},
			wantMerged:  []cookie.Cookie{liveLocal, livePeer},
			wantApplies: 1,
		},
		{
			name:        "dead-only difference triggers no apply",
			local:       []cookie.Cookie{liveLocal},
			peer:        []cookie.Cookie{liveLocal, expired, session},
			wantMerged:  []cookie.Cookie{liveLocal},
			wantApplies: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			local := &fakeSource{cookies: append([]cookie.Cookie(nil), tt.local...)}
			peer := &fakeSource{cookies: append([]cookie.Cookie(nil), tt.peer...)}
			self := "me@laptop"
			anchor := state.Endpoint{Host: self, Browser: "chrome", Profile: "Default"}
			peerEP := state.Endpoint{Host: "you@desktop", Browser: "chrome", Profile: "Default"}
			deps := ConvergeDeps{
				SelfTarget:  self,
				Cache:       warmCache{},
				Recorder:    &countingRecorder{},
				Baselines:   newMemBaselines(),
				LocalSource: local,
				SourceFor:   func(string) Source { return peer },
				LockFor:     testLockFor(),
			}

			merged, err := Converge(context.Background(), anchor, []state.Endpoint{peerEP}, "", deps)
			if err != nil {
				t.Fatalf("Converge: %v", err)
			}
			if !rowSetEqual(merged, tt.wantMerged) {
				t.Fatalf("merged = %+v, want %+v", merged, tt.wantMerged)
			}
			if len(local.applies) != tt.wantApplies || len(peer.applies) != tt.wantApplies {
				t.Fatalf("apply counts local=%d peer=%d, want %d each", len(local.applies), len(peer.applies), tt.wantApplies)
			}
			for endpoint, applies := range map[string][][]cookie.Cookie{"local": local.applies, "peer": peer.applies} {
				for _, applied := range applies {
					if !rowSetEqual(applied, tt.wantMerged) {
						t.Fatalf("%s apply payload = %+v, want %+v", endpoint, applied, tt.wantMerged)
					}
				}
			}
		})
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
		Baselines:   newMemBaselines(),
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

// TestConvergeIdempotentOnRerun proves a rerun over an already-converged group writes
// nothing, records nothing, and re-persists no baseline: the row sets already match
// the union, so apply_to is a no-op — the property the anti-echo relies on — and the
// rowcount ledger is saved only on the pass that changed it.
func TestConvergeIdempotentOnRerun(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	peerHost := "you@desktop"

	local := &fakeSource{cookies: []cookie.Cookie{ck(".x.com", "sid", "new", 200)}}
	peer := &fakeSource{cookies: []cookie.Cookie{ck(".x.com", "sid", "new", 200)}}
	rec := &countingRecorder{}
	baselines := newMemBaselines()
	deps := ConvergeDeps{
		SelfTarget:  self,
		Cache:       warmCache{},
		Recorder:    rec,
		Baselines:   baselines,
		LocalSource: local,
		SourceFor:   func(string) Source { return peer },
		LockFor:     testLockFor(),
	}
	anchor := state.Endpoint{Host: self, Browser: "chrome", Profile: "Default"}
	peerEP := state.Endpoint{Host: peerHost, Browser: "chrome", Profile: "Default"}

	for pass := 1; pass <= 2; pass++ {
		if _, err := Converge(ctx, anchor, []state.Endpoint{peerEP}, "", deps); err != nil {
			t.Fatalf("converge pass %d: %v", pass, err)
		}
	}
	if len(local.applies) != 0 || len(peer.applies) != 0 {
		t.Fatalf("already-equal endpoints should not be written: local=%d peer=%d", len(local.applies), len(peer.applies))
	}
	if len(rec.recorded) != 0 {
		t.Fatalf("no write means no recorded digest, got %d", len(rec.recorded))
	}
	if baselines.saves != 1 {
		t.Fatalf("baseline ledger saved %d times, want 1 (first pass only; the rerun changed nothing)", baselines.saves)
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
		Baselines:   newMemBaselines(),
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
		Baselines:   newMemBaselines(),
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
		Baselines:   newMemBaselines(),
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
		Baselines:   newMemBaselines(),
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
		Baselines:   newMemBaselines(),
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

// manyCk builds n distinct-name cookies stamped at lastUpdate, for baselines big
// enough to trip the quarantine thresholds.
func manyCk(n int, lastUpdate cookie.ChromeMicros) []cookie.Cookie {
	cookies := make([]cookie.Cookie, 0, n)
	for i := range n {
		cookies = append(cookies, ck(".x.com", fmt.Sprintf("bulk%04d", i), "v", lastUpdate))
	}
	return cookies
}

// quarantineDeps builds ConvergeDeps over local, peer, and a seeded baseline ledger.
func quarantineDeps(self string, local, peer *fakeSource, baselines *memBaselines) ConvergeDeps {
	return ConvergeDeps{
		SelfTarget:  self,
		Cache:       warmCache{},
		Recorder:    &countingRecorder{},
		Baselines:   baselines,
		LocalSource: local,
		SourceFor:   func(string) Source { return peer },
		LockFor:     testLockFor(),
	}
}

// TestConvergeQuarantinesMassDrop proves the merge-boundary quarantine: a local source
// whose extracted rowcount collapsed against its durable baseline is excluded from the
// merge inputs — its freshly-regenerated newest-stamped rows must not win per-key —
// while it still receives the merged union; sources above the thresholds stay in the
// merge and just track their baseline.
func TestConvergeQuarantinesMassDrop(t *testing.T) {
	self := "me@laptop"
	anchor := state.Endpoint{Host: self, Browser: "chrome", Profile: "Default"}
	peerEP := state.Endpoint{Host: "you@desktop", Browser: "chrome", Profile: "Default"}
	anchorID := string(anchor.ID())

	tests := []struct {
		name         string
		baseline     int
		local        []cookie.Cookie
		wantSID      string
		wantBaseline state.Baseline
	}{
		{
			name:     "collapsed local is excluded from merge but receives the union",
			baseline: 1000,
			local: []cookie.Cookie{
				ck(".x.com", "sid", "razed", 999),
				ck(".x.com", "regen", "R", 999),
			},
			wantSID:      "good",
			wantBaseline: state.Baseline{Rows: 1000, Quarantined: true, QuarantinedRows: 2},
		},
		{
			name:         "small baseline never quarantines",
			baseline:     100,
			local:        []cookie.Cookie{ck(".x.com", "sid", "razed", 999)},
			wantSID:      "razed",
			wantBaseline: state.Baseline{Rows: 1},
		},
		{
			name:         "drop above the collapse fraction stays healthy and re-baselines",
			baseline:     1000,
			local:        manyCk(60, 999),
			wantSID:      "good",
			wantBaseline: state.Baseline{Rows: 60},
		},
		{
			name:         "first pass records the baseline",
			baseline:     0,
			local:        []cookie.Cookie{ck(".x.com", "sid", "razed", 999)},
			wantSID:      "razed",
			wantBaseline: state.Baseline{Rows: 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			local := &fakeSource{cookies: append([]cookie.Cookie(nil), tt.local...)}
			peer := &fakeSource{cookies: []cookie.Cookie{ck(".x.com", "sid", "good", 200)}}
			baselines := newMemBaselines()
			if tt.baseline > 0 {
				baselines.baselines[anchorID] = state.Baseline{Rows: tt.baseline}
			}

			merged, err := Converge(ctx, anchor, []state.Endpoint{peerEP}, "", quarantineDeps(self, local, peer, baselines))
			if err != nil {
				t.Fatalf("Converge: %v", err)
			}

			values := map[string]string{}
			for _, c := range merged {
				values[c.Name] = c.Value
			}
			if values["sid"] != tt.wantSID {
				t.Fatalf("merged sid = %q, want %q", values["sid"], tt.wantSID)
			}
			if got := baselines.baselines[anchorID]; got != tt.wantBaseline {
				t.Fatalf("baseline = %+v, want %+v", got, tt.wantBaseline)
			}

			if !tt.wantBaseline.Quarantined {
				return
			}
			// Quarantined: no local-only row leaked into the union, yet the local store
			// still received the merged union.
			if _, ok := values["regen"]; ok {
				t.Fatalf("quarantined source's rows leaked into the merge: %v", values)
			}
			if len(local.applies) != 1 {
				t.Fatalf("quarantined source received %d applies, want 1 (the union write-back)", len(local.applies))
			}
			if !rowSetEqual(local.cookies, merged) {
				t.Fatalf("quarantined source holds %d rows after write-back, want the %d-row union", len(local.cookies), len(merged))
			}
		})
	}
}

// TestConvergeQuarantineSelfClears proves the union write-back heals a quarantined
// store past the recovery fraction, so the next pass clears the quarantine, resumes
// the baseline, and re-admits the source's rows to the merge.
func TestConvergeQuarantineSelfClears(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	anchor := state.Endpoint{Host: self, Browser: "chrome", Profile: "Default"}
	peerEP := state.Endpoint{Host: "you@desktop", Browser: "chrome", Profile: "Default"}
	anchorID := string(anchor.ID())

	local := &fakeSource{cookies: []cookie.Cookie{ck(".x.com", "sid", "razed", 999)}}
	peer := &fakeSource{cookies: append(manyCk(600, 100), ck(".x.com", "sid", "good", 200))}
	baselines := newMemBaselines()
	baselines.baselines[anchorID] = state.Baseline{Rows: 1000}
	deps := quarantineDeps(self, local, peer, baselines)

	if _, err := Converge(ctx, anchor, []state.Endpoint{peerEP}, "", deps); err != nil {
		t.Fatalf("first converge: %v", err)
	}
	if got := baselines.baselines[anchorID]; !got.Quarantined {
		t.Fatalf("first pass should quarantine, baseline = %+v", got)
	}
	if len(local.cookies) != 601 {
		t.Fatalf("union write-back left %d rows, want 601", len(local.cookies))
	}

	// The write-back restored 601 rows (>= 50%% of the 1000 baseline). The next pass
	// clears the quarantine and re-admits local rows: a new local-only cookie survives
	// into the union.
	local.cookies = append(local.cookies, ck(".x.com", "fresh", "F", 300))
	merged, err := Converge(ctx, anchor, []state.Endpoint{peerEP}, "", deps)
	if err != nil {
		t.Fatalf("second converge: %v", err)
	}
	if got, want := baselines.baselines[anchorID], (state.Baseline{Rows: 602}); got != want {
		t.Fatalf("post-recovery baseline = %+v, want %+v", got, want)
	}
	found := false
	for _, c := range merged {
		if c.Name == "fresh" {
			found = true
		}
	}
	if !found {
		t.Fatalf("recovered source's rows missing from the merge")
	}
}

// TestConvergeAllSourcesQuarantinedSkipsApply proves a converge with every source
// quarantined merges nothing and writes nothing — an empty union must never be applied
// over the one store that still has rows to recover elsewhere.
func TestConvergeAllSourcesQuarantinedSkipsApply(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	anchor := state.Endpoint{Host: self, Browser: "chrome", Profile: "Default"}
	anchorID := string(anchor.ID())

	local := &fakeSource{cookies: []cookie.Cookie{ck(".x.com", "sid", "razed", 999)}}
	baselines := newMemBaselines()
	baselines.baselines[anchorID] = state.Baseline{Rows: 1000}

	merged, err := Converge(ctx, anchor, nil, "", quarantineDeps(self, local, &fakeSource{}, baselines))
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if merged != nil {
		t.Fatalf("all-quarantined converge merged %d rows, want none", len(merged))
	}
	if len(local.applies) != 0 {
		t.Fatalf("all-quarantined converge wrote %d applies, want none", len(local.applies))
	}
}
