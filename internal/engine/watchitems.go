package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/syncservice"
)

// busyWriteWindow is how recently the cookie store (or a -journal/-wal sidecar) must
// have been written, with the owning browser running, for the item to report Busy —
// the signal synckitd's busy-gate defers on rather than fingerprinting a mid-write
// store.
const busyWriteWindow = 5 * time.Second

// WatchItems resolves this host's local endpoints from the mesh self, fingerprints each
// present one's cookie store decryption-free, and returns the watch items synckitd's
// watch supervisor drives. It is a pure read — no daemon, no Secure Enclave, no key — so
// the resident helper serves it freely behind svc.list. An endpoint whose profile
// directory does not exist yet (a registered target this host has not created) is
// skipped, matching the watch supervisor's per-id "no item" treatment. A per-endpoint
// read error is logged to stderr and the endpoint skipped, never failing the whole pass
// nor leaking onto the framing stdout. The items are sorted by id so the output is stable
// across the registry's unordered map.
func WatchItems(ctx context.Context, store StateLoader) ([]syncservice.WatchItem, error) {
	self, _, err := mesh.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	st, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]syncservice.WatchItem, 0)
	for _, ep := range st.Endpoints() {
		if ep.Host != self {
			continue
		}
		item, ok, err := watchItem(ctx, ep)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cookiesync: skip watch item %s: %v\n", ep.ID(), err)
			continue
		}
		if !ok {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

// StateLoader loads cookiesync's state. It is the read seam WatchItems resolves the
// tracked endpoints through, injected so the listing runs against a fixture state.
type StateLoader interface {
	Load(ctx context.Context) (*state.State, error)
}

// watchItem builds one endpoint's watch item: its id, its Cookies DB file (Chromium keeps
// the store in rollback-journal mode, not WAL, so every commit rewrites the Cookies file
// in place — watching that one file observes all writes, without the per-entry fd cost of
// watching the whole profile tree), and the apply-stable logical digest of its cookie
// store. The digest keys on (host_key, name, path, last_update_utc) and never decrypts,
// so a self-induced write (which preserves last_update_utc) reproduces it — that is what
// lets synckitd dedup cookiesync's own apply without a cross-process seed. An absent
// profile dir yields ok=false.
func watchItem(ctx context.Context, ep state.Endpoint) (syncservice.WatchItem, bool, error) {
	browser, err := cookie.Lookup(cookie.BrowserName(ep.Browser))
	if err != nil {
		return syncservice.WatchItem{}, false, err
	}
	dir := browser.ProfileDir(ep.Profile)
	if info, statErr := os.Stat(dir); statErr != nil || !info.IsDir() {
		return syncservice.WatchItem{}, false, nil
	}
	rows, err := cookie.Read(ctx, browser, ep.Profile)
	if err != nil {
		return syncservice.WatchItem{}, false, err
	}
	item := syncservice.WatchItem{
		ID:          string(ep.ID()),
		WatchDirs:   []string{browser.CookiesDB(ep.Profile)},
		Fingerprint: string(cookie.LogicalDigest(rows)),
	}
	if reason, busy := storeBusy(browser, ep.Profile, time.Now()); busy {
		item.Busy = true
		item.BusyReason = reason
	}
	return item, true, nil
}

// storeBusy reports whether the endpoint's store is plausibly mid-write: the Cookies
// file or a rollback-journal/WAL sidecar has an mtime within busyWriteWindow AND the
// owning browser is running. The mtime probe runs first — three stats — so an idle
// store never pays the process check.
func storeBusy(browser cookie.Browser, profile string, now time.Time) (string, bool) {
	db := browser.CookiesDB(profile)
	freshest := time.Duration(-1)
	for _, path := range []string{db, db + "-journal", db + "-wal"} {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if age := now.Sub(info.ModTime()); age < busyWriteWindow && (freshest < 0 || age < freshest) {
			freshest = age
		}
	}
	if freshest < 0 || !browserRunning(browser) {
		return "", false
	}
	return fmt.Sprintf("%s running and cookie store written %s ago", browser.Display, freshest.Round(time.Millisecond)), true
}

// browserRunning reports whether the browser owning this data root is up, read from
// the SingletonLock symlink Chromium keeps there (target "<hostname>-<pid>"). One
// readlink plus one signal-0 probe — no subprocess, unlike pgrep — and the pid probe
// discards a lock left stale by a crash.
func browserRunning(browser cookie.Browser) bool {
	target, err := os.Readlink(filepath.Join(browser.DataRoot, "SingletonLock"))
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(target[strings.LastIndexByte(target, '-')+1:])
	if err != nil || pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}
