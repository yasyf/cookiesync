package watch

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/state"
)

// NotifyHosts is the engine's fan-out list on a real change: this host first (the
// in-process local converge) then every distinct peer (an ssh-driven peer converge).
// Mirrors the Python notify_peers, which runs a local sync then a peer sync per host.
func NotifyHosts(st *state.State) []string {
	peers := engine.PeerHosts(st.Browsers, st.SelfTarget)
	hosts := make([]string, 0, len(peers)+1)
	hosts = append(hosts, st.SelfTarget)
	hosts = append(hosts, peers...)
	return hosts
}

// OnEvent feeds one filesystem event for the endpoint id into the engine's debounce.
// A burst across the Cookies DB and its sidecars coalesces into a single evaluate
// once the endpoint has been quiet for the debounce window.
func (e *Engine) OnEvent(ctx context.Context, id string) { e.core.OnEvent(ctx, id) }

// Run watches every present local endpoint's cookie store and converges on a real
// change until ctx is canceled. It loads state to find this host's present endpoints,
// opens one fsnotify watch per endpoint's profile directory (which holds the Cookies
// DB and its WAL/SHM sidecars), and maps each filesystem event back to its endpoint id
// to feed the engine. The engine debounces a write burst, fingerprints the store,
// suppresses the daemon's own echo, and on a genuine change converges locally and
// notifies every peer.
//
// The engine is built and owned by the caller (the daemon), so the same ledger seeds
// from a converge's recorded digest and dedups the induced filesystem event.
func (e *Engine) Run(ctx context.Context, store EndpointLookup) error {
	st, err := store.Load(ctx)
	if err != nil {
		return err
	}
	locals := localEndpoints(st)
	if len(locals) == 0 {
		slog.InfoContext(ctx, "watch: no local endpoints to watch; idling until cancelled")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer func() { _ = watcher.Close() }()

	dirs := map[string]string{} // watched profile dir -> endpoint id
	for _, ep := range locals {
		dir, ok := watchDir(ctx, ep)
		if !ok {
			continue
		}
		if err := watcher.Add(dir); err != nil {
			slog.WarnContext(ctx, "watch: cannot watch endpoint", "endpoint", ep.ID(), "dir", dir, "err", err)
			continue
		}
		dirs[dir] = string(ep.ID())
		slog.InfoContext(ctx, "watch: watching endpoint", "endpoint", ep.ID(), "dir", dir)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			// Every write to the Cookies DB or a -wal/-shm sidecar lands as an event
			// in the profile directory; map it back to its endpoint and debounce.
			if id, ok := dirs[filepath.Dir(event.Name)]; ok {
				e.OnEvent(ctx, id)
			}
		case watchErr, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			slog.WarnContext(ctx, "watch: fsnotify error", "err", watchErr)
		}
	}
}

// localEndpoints returns this host's present tracked endpoints — the ones whose stores
// live on this machine and so can be watched for local writes.
func localEndpoints(st *state.State) []state.Endpoint {
	var locals []state.Endpoint
	for _, e := range st.Endpoints() {
		if e.Host == st.SelfTarget {
			locals = append(locals, e)
		}
	}
	return locals
}

// watchDir returns the directory to watch for an endpoint — its profile directory,
// which holds the Cookies DB and its -wal/-shm sidecars, so a write burst across all
// three is observed. A profile directory that does not exist yet (a registered sync
// target this host has not created) is skipped rather than failing the whole loop.
func watchDir(ctx context.Context, e state.Endpoint) (string, bool) {
	browser, err := cookie.Lookup(cookie.BrowserName(e.Browser))
	if err != nil {
		slog.WarnContext(ctx, "watch: unknown browser, not watching", "endpoint", e.ID(), "err", err)
		return "", false
	}
	dir := browser.ProfileDir(e.Profile)
	if info, statErr := os.Stat(dir); statErr != nil || !info.IsDir() {
		slog.WarnContext(ctx, "watch: profile dir absent, not watching", "endpoint", e.ID(), "dir", dir)
		return "", false
	}
	return dir, true
}
