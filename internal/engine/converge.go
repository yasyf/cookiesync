package engine

import (
	"context"
	"log/slog"
	"sync"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
)

// Mass-drop quarantine thresholds: a local source whose extracted rowcount falls to
// QuarantineCollapseFraction of its last-known-good baseline (itself at least
// QuarantineMinBaseline rows) is excluded from merge inputs — a razed store's freshly
// regenerated cookies must not win per-key over good peer values — until it recovers
// to QuarantineRecoverFraction, which the union write-back itself achieves.
const (
	// QuarantineMinBaseline is the smallest baseline the quarantine acts on; below it
	// a collapse is indistinguishable from an ordinarily small store.
	QuarantineMinBaseline = 500
	// QuarantineCollapseFraction of baseline or fewer extracted rows quarantines.
	QuarantineCollapseFraction = 0.05
	// QuarantineRecoverFraction of baseline extracted rows clears a quarantine.
	QuarantineRecoverFraction = 0.5
)

// gathered is one endpoint's decrypted cookies for the union, with the source that
// yielded them, so the merged set can be applied back through the same seam. local
// marks a same-host endpoint, whose write-back runs under its apply lock; quarantined
// marks a local source excluded from merge inputs this pass (it still receives the
// union).
type gathered struct {
	endpoint    state.Endpoint
	source      Source
	cookies     []cookie.Cookie
	local       bool
	quarantined bool
}

// targetRow is the full value-bearing tuple used to decide whether an endpoint already
// holds a cookie. It covers every field a write would set, so an idempotent apply
// skips only when the stored row matches the winner exactly — including its preserved
// last_update_utc. Mirrors the Python sync.target_row.
type targetRow struct {
	hostKey              cookie.HostKey
	name                 string
	value                string
	path                 string
	expiresUTC           cookie.ChromeMicros
	lastUpdateUTC        cookie.ChromeMicros
	isSecure             bool
	isHTTPOnly           bool
	sameSite             int
	sourceScheme         int
	sourcePort           int
	topFrameSiteKey      string
	hasCrossSiteAncestor int
}

func rowOf(c cookie.Cookie) targetRow {
	return targetRow{
		hostKey:              c.HostKey,
		name:                 c.Name,
		value:                c.Value,
		path:                 c.Path,
		expiresUTC:           c.ExpiresUTC,
		lastUpdateUTC:        c.LastUpdateUTC,
		isSecure:             c.IsSecure,
		isHTTPOnly:           c.IsHTTPOnly,
		sameSite:             c.SameSite,
		sourceScheme:         c.SourceScheme,
		sourcePort:           c.SourcePort,
		topFrameSiteKey:      c.TopFrameSiteKey,
		hasCrossSiteAncestor: c.HasCrossSiteAncestor,
	}
}

// rowSetEqual reports whether two cookie sets hold the identical set of logical rows,
// ignoring order. When true, an apply would be a no-op and is skipped.
func rowSetEqual(a, b []cookie.Cookie) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[targetRow]int, len(a))
	for _, c := range a {
		counts[rowOf(c)]++
	}
	for _, c := range b {
		row := rowOf(c)
		counts[row]--
		if counts[row] < 0 {
			return false
		}
	}
	return true
}

// applyTo writes merged back to one gathered endpoint when its rows differ, recording
// the anti-echo digest before the write. It returns whether a write happened. When the
// endpoint already holds exactly the merged rows the write is skipped, so the converge
// is idempotent. A local endpoint's skip-check + record + write runs under its apply
// lock, serializing with the daemon's concurrent apply handler; a peer's apply crosses
// ssh unlocked. Mirrors the Python sync.apply_to.
func applyTo(ctx context.Context, g gathered, merged []cookie.Cookie, deps ConvergeDeps) (bool, error) {
	if g.local {
		defer deps.LockFor(string(g.endpoint.ID())).Unlock()
	}
	if rowSetEqual(merged, g.cookies) {
		return false, nil
	}
	deps.Recorder.RecordApplied(string(g.endpoint.ID()), cookie.LogicalDigest(merged))
	if _, err := g.source.Apply(ctx, g.endpoint.Browser, g.endpoint.Profile, merged); err != nil {
		return false, err
	}
	return true, nil
}

// BaselineStore persists each endpoint's last-known-good rowcount and quarantine flag
// across restarts. Baselines never returns a nil map; SaveBaselinesUnlocked runs
// inside the pass's already-held state flock.
type BaselineStore interface {
	Baselines(ctx context.Context) (map[string]state.Baseline, error)
	SaveBaselinesUnlocked(ctx context.Context, baselines map[string]state.Baseline) error
}

// ConvergeDeps bundles the injected collaborators a converge pass needs: the key cache
// for warmth checks, the local source for same-host endpoints, the recorder for the
// anti-echo digest, the durable rowcount ledger for the mass-drop quarantine, and the
// factory that builds a peer's Source.
type ConvergeDeps struct {
	SelfTarget  string
	Cache       KeyCache
	Recorder    cookie.Recorder
	Baselines   BaselineStore
	LocalSource Source
	// SourceFor builds the Source for a peer ssh target.
	SourceFor func(peer string) Source
	// LockFor acquires endpointID's apply lock and returns it held — the engine's
	// per-endpoint mutex shared with the daemon's apply handler. Only a local
	// endpoint's record+write pair runs under it, never a peer call.
	LockFor func(endpointID string) *sync.Mutex
}

// Converge merges the union of endpoint's cookies and every peer's across this host
// and its peers, then idempotently applies the merged set to every gathered endpoint.
//
// It gathers endpoint's cookies through the local source (a cold key cache returns
// ErrNeedsAuth rather than prompting), and each peer's through SourceFor(peer.host) —
// skipping any endpoint on the origin host so a sync is never echoed straight back to
// the host that triggered it, and skipping a cold same-host peer (logged, not silent).
// The union newest-wins cookie.Merge selects per cookie by raw last_update_utc — a
// local source the mass-drop quarantine flags is excluded from the merge inputs but
// still receives the union — and the result is written to any endpoint whose stored
// rows differ, the applied digest
// recorded before each write so the induced filesystem event is suppressed. A local
// write holds the endpoint's apply lock (LockFor), so it never interleaves with a
// concurrent peer-driven apply on the same store. It returns the merged set.
func Converge(
	ctx context.Context,
	endpoint state.Endpoint,
	peers []state.Endpoint,
	origin string,
	deps ConvergeDeps,
) ([]cookie.Cookie, error) {
	if _, ok, err := deps.Cache.Get(ctx, string(endpoint.ID())); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrNeedsAuth
	}

	sources := []gathered{{endpoint: endpoint, source: deps.LocalSource, local: true}}
	for _, peer := range peers {
		if peer.Host == origin {
			continue
		}
		if peer.Host == deps.SelfTarget {
			if _, ok, err := deps.Cache.Get(ctx, string(peer.ID())); err != nil {
				return nil, err
			} else if !ok {
				slog.WarnContext(ctx, "converge: skip cold same-host endpoint", "endpoint", peer.ID())
				continue
			}
			sources = append(sources, gathered{endpoint: peer, source: deps.LocalSource, local: true})
			continue
		}
		sources = append(sources, gathered{endpoint: peer, source: deps.SourceFor(peer.Host)})
	}

	for i := range sources {
		extracted, err := sources[i].source.Extract(ctx, sources[i].endpoint.Browser, sources[i].endpoint.Profile)
		if err != nil {
			return nil, err
		}
		sources[i].cookies = extracted.Cookies
	}

	if err := quarantineMassDrops(ctx, sources, deps); err != nil {
		return nil, err
	}

	sets := make([][]cookie.Cookie, 0, len(sources))
	for i := range sources {
		if sources[i].quarantined {
			continue
		}
		sets = append(sets, sources[i].cookies)
	}
	if len(sets) == 0 {
		slog.WarnContext(ctx, "converge: every source quarantined, nothing to merge", "endpoint", endpoint.ID())
		return nil, nil
	}
	merged := cookie.Merge(sets...)

	for _, g := range sources {
		if _, err := applyTo(ctx, g, merged, deps); err != nil {
			return nil, err
		}
	}
	return merged, nil
}

// quarantineMassDrops updates the durable rowcount ledger from this pass's local
// extractions and flags any local source whose rowcount collapsed against its
// baseline: it stays out of the merge inputs (but still receives the union) until it
// recovers to QuarantineRecoverFraction of baseline, at which point the quarantine
// clears and the baseline resumes tracking. The ledger is persisted only when changed.
func quarantineMassDrops(ctx context.Context, sources []gathered, deps ConvergeDeps) error {
	baselines, err := deps.Baselines.Baselines(ctx)
	if err != nil {
		return err
	}
	changed := false
	for i := range sources {
		if !sources[i].local {
			continue
		}
		id := string(sources[i].endpoint.ID())
		rows := len(sources[i].cookies)
		baseline, known := baselines[id]
		switch {
		case known && baseline.Quarantined && rows >= int(float64(baseline.Rows)*QuarantineRecoverFraction):
			slog.InfoContext(ctx, "converge: quarantine cleared, rowcount recovered",
				"endpoint", id, "rows", rows, "baseline", baseline.Rows)
			baselines[id] = state.Baseline{Rows: rows}
			changed = true
		case known && baseline.Quarantined:
			sources[i].quarantined = true
			slog.WarnContext(ctx, "converge: endpoint still quarantined, excluded from merge inputs",
				"endpoint", id, "rows", rows, "baseline", baseline.Rows)
		case known && baseline.Rows >= QuarantineMinBaseline && rows <= int(float64(baseline.Rows)*QuarantineCollapseFraction):
			sources[i].quarantined = true
			slog.ErrorContext(ctx, "converge: QUARANTINE: rowcount collapsed, excluding from merge inputs until recovery",
				"endpoint", id, "rows", rows, "baseline", baseline.Rows)
			baselines[id] = state.Baseline{Rows: baseline.Rows, Quarantined: true, QuarantinedRows: rows}
			changed = true
		case !known || baseline.Rows != rows:
			baselines[id] = state.Baseline{Rows: rows}
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return deps.Baselines.SaveBaselinesUnlocked(ctx, baselines)
}
