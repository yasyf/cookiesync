package bridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/yasyf/cookiesync/internal/cookie"
)

// windowsEpochOffset mirrors cookie.windowsEpochOffset: seconds between the
// Windows epoch (1601) and the Unix epoch (1970).
const windowsEpochOffset = 11_644_473_600

// SeedReport summarizes what was injected and what was dropped.
// SessionStorageOrigins counts origins seeded on the OTR page; that
// sessionStorage is tab-scoped and survives only while the external client keeps
// driving the seeded tab (a fresh tab starts empty).
type SeedReport struct {
	Cookies, LocalStorageOrigins, SessionStorageOrigins, SkippedCookies int
}

// Seed provisions an off-the-record CDP browser context, seeds it, and leaves a
// single blank page in it for the external client to attach to. The context
// comes from Target.createBrowserContext (disposeOnDetach ties its lifetime to
// the pipe, i.e. Chrome shutdown), so the decrypted cookies and web storage live
// only in Chrome's memory and never persist to the on-disk --user-data-dir. Web
// storage seeds first — its synthetic navigations run offline and never carry
// auth cookies — then cookies land last in one context-scoped Storage.setCookies.
// The client must drive this sole seeded page: a fresh default-context page
// (e.g. a raw Playwright newPage()) sees none of the OTR cookies by design.
func Seed(ctx context.Context, c *Conn, state cookie.StorageState) (SeedReport, error) {
	hub := &seedEvents{}
	fn := hub.dispatch
	c.proc.events.Store(&fn)
	defer c.proc.events.Store(nil)

	var report SeedReport

	browserContextID, err := createBrowserContext(ctx, c)
	if err != nil {
		return report, err
	}

	pageID, err := createTarget(ctx, c, browserContextID)
	if err != nil {
		return report, err
	}

	local, session, err := seedWebStorage(ctx, c, hub, pageID, state.Origins)
	if err != nil {
		return report, err
	}
	report.LocalStorageOrigins = local
	report.SessionStorageOrigins = session

	accepted, skipped, err := seedCookies(ctx, c, browserContextID, state.Cookies)
	if err != nil {
		return report, err
	}
	report.Cookies = accepted
	report.SkippedCookies = skipped

	if err := closeOtherPages(ctx, c, pageID); err != nil {
		return report, err
	}
	return report, nil
}

// seedWebStorage seeds every origin's local/session storage on the single OTR
// page, navigating it through each origin in turn. localStorage is context-
// scoped and persists in Chrome's memory; sessionStorage is tab-scoped and
// survives only while the external client keeps driving this same page. The page
// is returned to about:blank and the seeding session detached (dropping its
// Fetch interception) before the client attaches.
func seedWebStorage(ctx context.Context, c *Conn, hub *seedEvents, pageID string, origins []cookie.OriginStorage) (local, session int, err error) {
	var work []cookie.OriginStorage
	for _, o := range origins {
		if !seedableOrigin(o.Origin) {
			continue
		}
		if len(o.LocalStorage) > 0 || len(o.SessionStorage) > 0 {
			work = append(work, o)
		}
	}
	if len(work) == 0 {
		return 0, 0, nil
	}

	sessionID, err := attachTarget(ctx, c, pageID)
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		_, _ = c.Call(ctx, "", "Target.detachFromTarget", map[string]any{"sessionId": sessionID})
	}()

	if _, err := c.Call(ctx, sessionID, "Fetch.enable", nil); err != nil {
		return 0, 0, fmt.Errorf("fetch enable: %w", err)
	}
	if _, err := c.Call(ctx, sessionID, "Page.enable", nil); err != nil {
		return 0, 0, fmt.Errorf("page enable: %w", err)
	}

	paused := hub.subscribe(sessionID, "Fetch.requestPaused", 32)
	defer hub.unsubscribe(paused)
	stop := make(chan struct{})
	defer close(stop)
	go fulfillLoop(ctx, c, sessionID, paused.ch, stop)

	for _, o := range work {
		if err := navigateAndWait(ctx, c, hub, sessionID, o.Origin); err != nil {
			return local, session, fmt.Errorf("seed web storage for %s: %w", o.Origin, err)
		}
		if len(o.LocalStorage) > 0 {
			if err := setStorage(ctx, c, sessionID, "localStorage", o.LocalStorage); err != nil {
				return local, session, fmt.Errorf("set localStorage for %s: %w", o.Origin, err)
			}
			local++
		}
		if len(o.SessionStorage) > 0 {
			if err := setStorage(ctx, c, sessionID, "sessionStorage", o.SessionStorage); err != nil {
				return local, session, fmt.Errorf("set sessionStorage for %s: %w", o.Origin, err)
			}
			session++
		}
	}

	if err := navigateAndWait(ctx, c, hub, sessionID, "about:blank"); err != nil {
		return local, session, fmt.Errorf("reset seed page: %w", err)
	}
	return local, session, nil
}

// seedableOrigin reports whether an origin's web storage can be replayed: only
// http(s) accepts a Page.navigate + localStorage write, and privileged schemes
// (chrome-extension://, chrome://, devtools://) deny it.
func seedableOrigin(origin string) bool {
	return strings.HasPrefix(origin, "https://") || strings.HasPrefix(origin, "http://")
}

// navigateAndWait drives one navigation on the seeding session and blocks until
// the page's load event fires (offline navigations are fulfilled by fulfillLoop).
func navigateAndWait(ctx context.Context, c *Conn, hub *seedEvents, sessionID, url string) error {
	loaded := hub.subscribe(sessionID, "Page.loadEventFired", 1)
	defer hub.unsubscribe(loaded)
	if _, err := c.Call(ctx, sessionID, "Page.navigate", map[string]any{"url": url}); err != nil {
		return fmt.Errorf("navigate %s: %w", url, err)
	}
	select {
	case <-loaded.ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// fulfillLoop answers every intercepted request with an empty offline 200 until
// stop closes, keeping seeding deterministic (no network hit, redirect, or
// telemetry against the user's live session).
func fulfillLoop(ctx context.Context, c *Conn, sessionID string, paused <-chan cdpMessage, stop <-chan struct{}) {
	body := base64.StdEncoding.EncodeToString(nil)
	for {
		select {
		case msg := <-paused:
			var ev struct {
				RequestID string `json:"requestId"`
			}
			if err := json.Unmarshal(msg.Params, &ev); err != nil {
				continue
			}
			_, _ = c.Call(ctx, sessionID, "Fetch.fulfillRequest", map[string]any{
				"requestId":       ev.RequestID,
				"responseCode":    200,
				"responseHeaders": []map[string]string{{"name": "Content-Type", "value": "text/html; charset=utf-8"}},
				"body":            body,
			})
		case <-stop:
			return
		case <-ctx.Done():
			return
		}
	}
}

// setStorage writes each entry into area ("localStorage"/"sessionStorage") by
// evaluating a setter function handle, then invoking it with the key and value
// as CallArguments — never interpolating either into JS source.
func setStorage(ctx context.Context, c *Conn, sessionID, area string, entries []cookie.WebStorageEntry) error {
	raw, err := c.Call(ctx, sessionID, "Runtime.evaluate", map[string]any{
		"expression":    "(function(k, v){ " + area + ".setItem(k, v); })",
		"returnByValue": false,
	})
	if err != nil {
		return fmt.Errorf("evaluate setter: %w", err)
	}
	var eval struct {
		Result struct {
			ObjectID string `json:"objectId"`
		} `json:"result"`
		ExceptionDetails json.RawMessage `json:"exceptionDetails"`
	}
	if err := json.Unmarshal(raw, &eval); err != nil {
		return fmt.Errorf("decode setter handle: %w", err)
	}
	if eval.ExceptionDetails != nil {
		return fmt.Errorf("evaluate setter: %s", eval.ExceptionDetails)
	}
	if eval.Result.ObjectID == "" {
		return fmt.Errorf("evaluate setter: no objectId")
	}

	for _, e := range entries {
		res, err := c.Call(ctx, sessionID, "Runtime.callFunctionOn", map[string]any{
			"objectId":            eval.Result.ObjectID,
			"functionDeclaration": "function(k, v){ return this(k, v); }",
			"arguments":           []map[string]any{{"value": e.Name}, {"value": e.Value}},
			"returnByValue":       true,
		})
		if err != nil {
			return fmt.Errorf("set %s %q: %w", area, e.Name, err)
		}
		var call struct {
			ExceptionDetails json.RawMessage `json:"exceptionDetails"`
		}
		if err := json.Unmarshal(res, &call); err != nil {
			return fmt.Errorf("decode set %s result: %w", area, err)
		}
		if call.ExceptionDetails != nil {
			return fmt.Errorf("set %s %q: %s", area, e.Name, call.ExceptionDetails)
		}
	}
	return nil
}

// createBrowserContext opens an off-the-record CDP browser context whose cookies
// and storage live only in Chrome's memory. disposeOnDetach ties the context to
// the pipe: Chrome tears it down when the CDP connection drops (i.e. shutdown).
func createBrowserContext(ctx context.Context, c *Conn) (string, error) {
	raw, err := c.Call(ctx, "", "Target.createBrowserContext", map[string]any{"disposeOnDetach": true})
	if err != nil {
		return "", fmt.Errorf("create browser context: %w", err)
	}
	var res struct {
		BrowserContextID string `json:"browserContextId"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return "", fmt.Errorf("decode createBrowserContext: %w", err)
	}
	return res.BrowserContextID, nil
}

func createTarget(ctx context.Context, c *Conn, browserContextID string) (string, error) {
	raw, err := c.Call(ctx, "", "Target.createTarget", map[string]any{"url": "about:blank", "browserContextId": browserContextID})
	if err != nil {
		return "", fmt.Errorf("create target: %w", err)
	}
	var res struct {
		TargetID string `json:"targetId"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return "", fmt.Errorf("decode createTarget: %w", err)
	}
	return res.TargetID, nil
}

// closeOtherPages closes every page target except keep. With --no-startup-window
// the OTR seeded page is normally the only one, so this closes nothing; it stays
// a cheap safety net against any stray or future default-context page.
func closeOtherPages(ctx context.Context, c *Conn, keep string) error {
	raw, err := c.Call(ctx, "", "Target.getTargets", nil)
	if err != nil {
		return fmt.Errorf("get targets: %w", err)
	}
	var res struct {
		TargetInfos []struct {
			TargetID string `json:"targetId"`
			Type     string `json:"type"`
		} `json:"targetInfos"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("decode getTargets: %w", err)
	}
	for _, t := range res.TargetInfos {
		if t.Type != "page" || t.TargetID == keep {
			continue
		}
		if _, err := c.Call(ctx, "", "Target.closeTarget", map[string]any{"targetId": t.TargetID}); err != nil {
			return fmt.Errorf("close startup page %s: %w", t.TargetID, err)
		}
	}
	return nil
}

func attachTarget(ctx context.Context, c *Conn, targetID string) (string, error) {
	raw, err := c.Call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": targetID, "flatten": true})
	if err != nil {
		return "", fmt.Errorf("attach target: %w", err)
	}
	var res struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return "", fmt.Errorf("decode attachToTarget: %w", err)
	}
	return res.SessionID, nil
}

// seedCookies sets every cookie into the OTR context in one Storage.setCookies
// batch, isolating the good ones per-cookie if the batch is rejected (typically
// an unsupported partitionKey shape), then reads back to count what Chrome
// actually accepted.
func seedCookies(ctx context.Context, c *Conn, browserContextID string, cookies []cookie.Cookie) (accepted, skipped int, err error) {
	if len(cookies) == 0 {
		return 0, 0, nil
	}
	params := make([]cdpCookieParam, len(cookies))
	for i, ck := range cookies {
		params[i] = toCookieParam(ck)
	}

	if _, err := c.Call(ctx, "", "Storage.setCookies", map[string]any{"cookies": params, "browserContextId": browserContextID}); err != nil {
		for _, p := range params {
			_, _ = c.Call(ctx, "", "Storage.setCookies", map[string]any{"cookies": []cdpCookieParam{p}, "browserContextId": browserContextID})
		}
	}

	got, err := getCookieCount(ctx, c, browserContextID)
	if err != nil {
		return 0, 0, err
	}
	skipped = len(params) - got
	if skipped < 0 {
		skipped = 0
	}
	return got, skipped, nil
}

func getCookieCount(ctx context.Context, c *Conn, browserContextID string) (int, error) {
	raw, err := c.Call(ctx, "", "Storage.getCookies", map[string]any{"browserContextId": browserContextID})
	if err != nil {
		return 0, fmt.Errorf("get cookies: %w", err)
	}
	var res struct {
		Cookies []json.RawMessage `json:"cookies"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("decode getCookies: %w", err)
	}
	return len(res.Cookies), nil
}

// cdpCookieParam is Network.CookieParam: the fields Storage.setCookies reads.
type cdpCookieParam struct {
	Name         string                 `json:"name"`
	Value        string                 `json:"value"`
	URL          string                 `json:"url,omitempty"`
	Domain       string                 `json:"domain,omitempty"`
	Path         string                 `json:"path,omitempty"`
	Secure       bool                   `json:"secure,omitempty"`
	HTTPOnly     bool                   `json:"httpOnly,omitempty"`
	SameSite     string                 `json:"sameSite,omitempty"`
	Expires      float64                `json:"expires,omitempty"`
	SourceScheme string                 `json:"sourceScheme,omitempty"`
	SourcePort   int                    `json:"sourcePort,omitempty"`
	PartitionKey *cdpCookiePartitionKey `json:"partitionKey,omitempty"`
}

// cdpCookiePartitionKey is Network.CookiePartitionKey (Chrome 117+ object shape).
type cdpCookiePartitionKey struct {
	TopLevelSite         string `json:"topLevelSite"`
	HasCrossSiteAncestor bool   `json:"hasCrossSiteAncestor"`
}

// toCookieParam maps a native Chrome cookie to Network.CookieParam, preserving
// host-only vs domain scope, the SameSite=None secure coupling, unspecified
// SameSite (omitted, not Lax), session expiry, source scheme/port, and the
// CHIPS partition key.
func toCookieParam(c cookie.Cookie) cdpCookieParam {
	sameSiteNone := c.SameSite == 0
	secure := c.IsSecure || sameSiteNone

	p := cdpCookieParam{
		Name:     c.Name,
		Value:    c.Value,
		Path:     c.Path,
		Secure:   secure,
		HTTPOnly: c.IsHTTPOnly,
	}

	if len(c.HostKey) > 0 && c.HostKey[0] == '.' {
		p.Domain = string(c.HostKey)
	} else {
		scheme := "http"
		if secure {
			scheme = "https"
		}
		p.URL = scheme + "://" + string(c.HostKey) + c.Path
	}

	switch c.SameSite {
	case 0:
		p.SameSite = "None"
	case 1:
		p.SameSite = "Lax"
	case 2:
		p.SameSite = "Strict"
	}

	if seconds, sessionCookie := chromeMicrosToUnix(c.ExpiresUTC); !sessionCookie {
		p.Expires = seconds
	}

	switch c.SourceScheme {
	case 1:
		p.SourceScheme = "NonSecure"
	case 2:
		p.SourceScheme = "Secure"
	}
	if c.SourcePort > 0 {
		p.SourcePort = c.SourcePort
	}

	if c.TopFrameSiteKey != "" {
		p.PartitionKey = &cdpCookiePartitionKey{
			TopLevelSite:         c.TopFrameSiteKey,
			HasCrossSiteAncestor: c.HasCrossSiteAncestor != 0,
		}
	}

	return p
}

// chromeMicrosToUnix mirrors cookie.chromeMicrosToUnix: it converts a Chrome
// timestamp (µs since 1601) to Unix seconds, reporting a non-positive value as a
// session cookie.
func chromeMicrosToUnix(micros cookie.ChromeMicros) (seconds float64, session bool) {
	if micros <= 0 {
		return 0, true
	}
	r := new(big.Rat).SetFrac(big.NewInt(int64(micros)), big.NewInt(1_000_000))
	f, _ := r.Float64()
	return f - windowsEpochOffset, false
}

// seedEvents fans id-less CDP events out to per-(session,method) subscribers
// with non-blocking sends, so the pipe read-loop never blocks on a slow waiter.
type seedEvents struct {
	mu   sync.Mutex
	subs map[*seedSub]struct{}
}

type seedSub struct {
	session string
	method  string
	ch      chan cdpMessage
}

func (e *seedEvents) subscribe(session, method string, buf int) *seedSub {
	sub := &seedSub{session: session, method: method, ch: make(chan cdpMessage, buf)}
	e.mu.Lock()
	if e.subs == nil {
		e.subs = map[*seedSub]struct{}{}
	}
	e.subs[sub] = struct{}{}
	e.mu.Unlock()
	return sub
}

func (e *seedEvents) unsubscribe(sub *seedSub) {
	e.mu.Lock()
	delete(e.subs, sub)
	e.mu.Unlock()
}

func (e *seedEvents) dispatch(msg cdpMessage) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for sub := range e.subs {
		if sub.method != msg.Method || (sub.session != "" && sub.session != msg.SessionID) {
			continue
		}
		select {
		case sub.ch <- msg:
		default:
		}
	}
}
