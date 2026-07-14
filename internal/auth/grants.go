package auth

import (
	"context"
	"fmt"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yasyf/cookiesync/internal/cache"
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/synckit/presence"
)

// degradedAuthTTL caps the consent-grant window whenever a release published a
// key under a degraded (process-memory) cache epoch, mirroring the cache's own
// entry cap: RAM-only keys, and the grants that let them be served silently,
// never outlive a short window.
const degradedAuthTTL = cache.DegradedTTL

// Granted reports whether requestor holds a live grant for browser, pruning
// every expired grant on the way.
func (b *Broker) Granted(requestor string, browser cookie.BrowserName) bool {
	now := time.Now()
	b.grantMu.Lock()
	defer b.grantMu.Unlock()
	for key, expiry := range b.grants {
		if now.After(expiry) {
			delete(b.grants, key)
		}
	}
	_, ok := b.grants[requestor+":"+string(browser)]
	return ok
}

// Grant authorizes requestor for every browser a release covered, expiring
// after ttl.
func (b *Broker) Grant(requestor string, browsers []cookie.BrowserName, ttl time.Duration) {
	expiry := time.Now().Add(ttl)
	b.grantMu.Lock()
	defer b.grantMu.Unlock()
	for _, browser := range browsers {
		b.grants[requestor+":"+string(browser)] = expiry
	}
}

// CapGrant shortens requestor's live grant for browser to expire no later than
// now + ttl. It only ever moves an expiry earlier — never creating or extending
// authority — and is a no-op when no grant exists.
func (b *Broker) CapGrant(requestor string, browser cookie.BrowserName, ttl time.Duration) {
	capped := time.Now().Add(ttl)
	b.grantMu.Lock()
	defer b.grantMu.Unlock()
	key := requestor + ":" + string(browser)
	if expiry, ok := b.grants[key]; ok && expiry.After(capped) {
		b.grants[key] = capped
	}
}

// effectiveTTL is the single derivation point for a release's grant window: the
// configured AuthTTL, capped to degradedAuthTTL when the release's Puts report
// publishing under a degraded epoch. It derives from the reported publish
// outcome — never a pre-Put probe, which a mid-call demote or heal would stale
// out.
func effectiveTTL(configured time.Duration, publishedDegraded bool) time.Duration {
	if publishedDegraded && configured > degradedAuthTTL {
		return degradedAuthTTL
	}
	return configured
}

// requestorReason weaves a display name into the Touch ID reason ("sync them
// across your Macs for claude") — best-effort: any failure resolving the name
// leaves the reason as is, never failing the release. A "req:" requestor names
// itself from its token with zero subprocess; otherwise a captured peer pid
// resolves the calling process's name. The pid is passed in separately rather
// than recovered from the requestor string, so the display name is decoupled
// from the grant key.
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

// keybagLocked reports whether the data-protection keybag is unavailable to the
// daemon user: the console screen is locked, headless (no GUI session), or held
// by another user via fast user switching. Unlike presence.Attended it ignores
// ScreenShared — a mirrored unlocked session still decrypts, so screen-share
// bears on consent routing, not keybag availability.
func keybagLocked(snapshot presence.SessionSnapshot) (bool, error) {
	me, err := user.Current()
	if err != nil {
		return false, fmt.Errorf("resolve current user: %w", err)
	}
	return snapshot.Locked || !snapshot.OnConsole || snapshot.ConsoleUser != me.Username, nil
}
