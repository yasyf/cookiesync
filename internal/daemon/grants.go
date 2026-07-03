package daemon

import (
	"context"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	synckit "github.com/yasyf/synckit/rpc"
)

// degradedAuthTTL caps the key-cache TTL and the consent-grant window while the key
// cache is degraded to process memory: RAM-only keys, and the grants that let them be
// served silently, never outlive a short window.
const degradedAuthTTL = 5 * time.Minute

// requestorID resolves the LOCAL principal a request acts for. It never reads
// origin, so a same-uid local process cannot forge a host grant on a local method.
// An explicit requestor token wins ("req:" + token); otherwise the local
// unix-socket client's login session keys the grant ("sid:" + peer session id); a
// transport with neither (tests, ServeConn) is "local".
func requestorID(ctx context.Context, params map[string]any) string {
	if tok := optionalString(params, "requestor", ""); tok != "" {
		return "req:" + tok
	}
	if sid, ok := synckit.PeerSID(ctx); ok {
		return "sid:" + strconv.Itoa(sid)
	}
	return "local"
}

// peerRequestor is requestorID for the two methods a remote peer drives: extract and
// the single-browser get_cookies. A peer forwards its mesh self as the origin param,
// which keys the grant ("host:" + origin); with no origin it falls back to the local
// requestorID ladder.
func peerRequestor(ctx context.Context, params map[string]any) string {
	if origin := optionalString(params, "origin", ""); origin != "" {
		return "host:" + origin
	}
	return requestorID(ctx, params)
}

// granted reports whether requestor holds a live grant for browser, pruning every
// expired grant on the way.
func (d *Daemon) granted(requestor string, browser cookie.BrowserName) bool {
	now := time.Now()
	d.grantMu.Lock()
	defer d.grantMu.Unlock()
	for key, expiry := range d.grants {
		if now.After(expiry) {
			delete(d.grants, key)
		}
	}
	_, ok := d.grants[requestor+":"+string(browser)]
	return ok
}

// grant authorizes requestor for every browser a release covered, expiring after ttl.
func (d *Daemon) grant(requestor string, browsers []cookie.BrowserName, ttl time.Duration) {
	expiry := time.Now().Add(ttl)
	d.grantMu.Lock()
	defer d.grantMu.Unlock()
	for _, b := range browsers {
		d.grants[requestor+":"+string(b)] = expiry
	}
}

// effectiveTTL is the single derivation point for how long a released key stays
// cached and its grant stays live: the configured AuthTTL, capped to degradedAuthTTL
// while the key cache is degraded to process memory.
func (d *Daemon) effectiveTTL(configured time.Duration) time.Duration {
	if d.cache.Degraded() && configured > degradedAuthTTL {
		return degradedAuthTTL
	}
	return configured
}

// requestorReason weaves a display name into the Touch ID reason ("sync them across
// your Macs for claude") — best-effort: any failure resolving the name leaves the
// reason as is, never failing the release. A "req:" requestor names itself from its
// token with zero subprocess; otherwise a captured peer pid resolves the calling
// process's name. The pid is passed in separately (from synckit.PeerPID) rather than
// recovered from the requestor string, so the display name is decoupled from the
// grant key.
func requestorReason(ctx context.Context, requestor, reason string, pid int, hasPID bool) string {
	if tok, ok := strings.CutPrefix(requestor, "req:"); ok {
		return reason + " for " + tok
	}
	if !hasPID {
		return reason
	}
	out, err := exec.CommandContext(ctx, "ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output() //nolint:gosec // G204: pid is an int rendered to string, not user-supplied text; no injection surface.
	if err != nil {
		return reason
	}
	name := strings.TrimSpace(string(out))
	if name == "" {
		return reason
	}
	return reason + " for " + filepath.Base(name)
}
