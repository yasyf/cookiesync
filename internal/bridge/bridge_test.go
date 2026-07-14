package bridge

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver for the on-disk proof

	"github.com/yasyf/cookiesync/internal/cookie"
)

func TestBridgeSeedAndServe(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: launches a real Chrome")
	}
	bin, err := ResolveHostBinary()
	if err != nil {
		t.Skipf("skipping: Chrome not installed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dataDir := t.TempDir()
	proc, err := Launch(ctx, LaunchSpec{HostBinary: bin, DataDir: dataDir, Headed: false})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	t.Cleanup(func() { _ = proc.Close() })

	conn, err := proc.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Distinctive names/values the on-disk scan keys on: cookie names and host
	// keys are plaintext in the jar, the localStorage value in the LevelDB.
	state := cookie.StorageState{
		Cookies: []cookie.Cookie{
			{
				HostKey: "example.com", Name: "otrproof_hostonly", Value: "otrproofval1", Path: "/",
				IsSecure: true, SameSite: 2, SourceScheme: 2, SourcePort: 443,
			},
			{
				HostKey: ".example.org", Name: "otrproof_domain", Value: "otrproofval2", Path: "/",
				IsSecure: false, SameSite: 1, SourceScheme: 1, SourcePort: 80,
			},
		},
		Origins: []cookie.OriginStorage{
			{
				Origin:       "https://example.com",
				LocalStorage: []cookie.WebStorageEntry{{Name: "otrproof_ls", Value: "otrproofls1"}},
			},
		},
	}

	report, err := Seed(ctx, conn, state)
	if err != nil {
		t.Fatalf("Seed: %v (chrome stderr: %q)", err, proc.stderr.String())
	}
	if report.Cookies != 2 {
		t.Errorf("report.Cookies = %d, want 2", report.Cookies)
	}
	if report.SkippedCookies != 0 {
		t.Errorf("report.SkippedCookies = %d, want 0", report.SkippedCookies)
	}
	if report.LocalStorageOrigins != 1 {
		t.Errorf("report.LocalStorageOrigins = %d, want 1", report.LocalStorageOrigins)
	}
	if report.SessionStorageOrigins != 0 {
		t.Errorf("report.SessionStorageOrigins = %d, want 0", report.SessionStorageOrigins)
	}

	const token = "s3cr3t-bridge-token"
	srv, err := proc.Serve(ctx, token, "")
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	// /json/version with the token advertises the ws endpoint.
	verResp, err := http.Get("http://" + srv.Addr() + "/" + token + "/json/version")
	if err != nil {
		t.Fatalf("GET /json/version: %v", err)
	}
	if verResp.StatusCode != http.StatusOK {
		t.Fatalf("/json/version status = %d, want 200", verResp.StatusCode)
	}
	var ver struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(verResp.Body).Decode(&ver); err != nil {
		t.Fatalf("decode /json/version: %v", err)
	}
	_ = verResp.Body.Close()
	if ver.WebSocketDebuggerURL != srv.URL() {
		t.Errorf("webSocketDebuggerUrl = %q, want %q", ver.WebSocketDebuggerURL, srv.URL())
	}

	// Bare /json/version without the token is rejected.
	bareResp, err := http.Get("http://" + srv.Addr() + "/json/version")
	if err != nil {
		t.Fatalf("GET bare /json/version: %v", err)
	}
	_ = bareResp.Body.Close()
	if bareResp.StatusCode != http.StatusForbidden {
		t.Errorf("bare /json/version status = %d, want 403", bareResp.StatusCode)
	}

	// The single external client relays raw CDP frames through the pipe.
	client, _, err := dialClient(ctx, srv.URL())
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}

	// Exactly one page target must exist — the OTR seeded page — so a client's
	// default "attach to the existing page" lands on it, not a startup page.
	pageID, browserCtxID := soleSeededPage(ctx, t, client)

	// The OTR context holds both cookies with full attribute fidelity.
	assertOTRCookies(ctx, t, client, browserCtxID)

	// The default (on-disk-backed) context is empty: nothing can flush to disk.
	if n := cookieCount(ctx, t, client, ""); n != 0 {
		t.Errorf("default-context cookies = %d, want 0 (seeded cookies must live only in the OTR context)", n)
	}

	// Real attach flow: attach to the OTR page, drive it to https://example.com
	// offline, and confirm the seeded cookie is readable there.
	assertClientReachesCookie(ctx, t, client, pageID)

	// A wrong token is rejected at the handshake.
	wrongURL := fmt.Sprintf("ws://%s/%s/devtools/browser/%s", srv.Addr(), "wrong-token", proc.BrowserUUID())
	if _, resp, err := websocket.Dial(ctx, wrongURL, nil); err == nil {
		t.Errorf("wrong-token dial succeeded, want rejection")
	} else if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("wrong-token dial status = %v, want 403", statusOf(resp))
	}

	// A second concurrent client is rejected while the first is live.
	if _, resp, err := websocket.Dial(ctx, srv.URL(), nil); err == nil {
		t.Errorf("second client dial succeeded, want rejection")
	} else if resp == nil || resp.StatusCode != http.StatusConflict {
		t.Errorf("second client dial status = %v, want 409", statusOf(resp))
	}

	// The decrypted session never touched the on-disk --user-data-dir.
	assertSeededDataNotOnDisk(t, dataDir)

	// Closing the client fires Done.
	_ = client.c.Close(websocket.StatusNormalClosure, "")
	select {
	case <-srv.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("Done not fired after client close")
	}
}

// TestBridgeSeedCookieOnlySolePage guards the cookie-only seed path — Origins
// empty, so no web-storage navigation runs — which previously raced a default-
// context startup page. --no-startup-window must leave exactly one page target,
// in the OTR context, holding the seeded cookies.
func TestBridgeSeedCookieOnlySolePage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: launches a real Chrome")
	}
	bin, err := ResolveHostBinary()
	if err != nil {
		t.Skipf("skipping: Chrome not installed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	proc, err := Launch(ctx, LaunchSpec{HostBinary: bin, DataDir: t.TempDir(), Headed: false})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	t.Cleanup(func() { _ = proc.Close() })

	conn, err := proc.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Cookie-only: Origins empty, so seedWebStorage is a no-op and the OTR page
	// is never navigated — the path that previously raced a startup page.
	state := cookie.StorageState{
		Cookies: []cookie.Cookie{
			{
				HostKey: "example.com", Name: "otrproof_hostonly", Value: "otrproofval1", Path: "/",
				IsSecure: true, SameSite: 2, SourceScheme: 2, SourcePort: 443,
			},
			{
				HostKey: ".example.org", Name: "otrproof_domain", Value: "otrproofval2", Path: "/",
				IsSecure: false, SameSite: 1, SourceScheme: 1, SourcePort: 80,
			},
		},
	}
	report, err := Seed(ctx, conn, state)
	if err != nil {
		t.Fatalf("Seed: %v (chrome stderr: %q)", err, proc.stderr.String())
	}
	if report.Cookies != 2 {
		t.Errorf("report.Cookies = %d, want 2", report.Cookies)
	}
	if report.LocalStorageOrigins != 0 || report.SessionStorageOrigins != 0 {
		t.Errorf("web-storage origins = %d local / %d session, want 0/0 (cookie-only)", report.LocalStorageOrigins, report.SessionStorageOrigins)
	}

	const token = "s3cr3t-bridge-token"
	srv, err := proc.Serve(ctx, token, "")
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	client, _, err := dialClient(ctx, srv.URL())
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}

	// Exactly one page target, in an OTR (non-empty) context — no startup page.
	_, browserCtxID := soleSeededPage(ctx, t, client)

	// The seeded cookies live at that OTR scope with full attribute fidelity.
	assertOTRCookies(ctx, t, client, browserCtxID)

	// The default (on-disk-backed) context holds none.
	if n := cookieCount(ctx, t, client, ""); n != 0 {
		t.Errorf("default-context cookies = %d, want 0 (seeded cookies must live only in the OTR context)", n)
	}
}

// soleSeededPage returns the single page target and its OTR browser context id,
// failing if the browser exposes anything other than exactly one page.
func soleSeededPage(ctx context.Context, t *testing.T, client *wsClient) (targetID, browserContextID string) {
	t.Helper()
	raw, err := client.call(ctx, "", "Target.getTargets", nil)
	if err != nil {
		t.Fatalf("Target.getTargets over relay: %v", err)
	}
	var res struct {
		TargetInfos []struct {
			TargetID         string `json:"targetId"`
			Type             string `json:"type"`
			BrowserContextID string `json:"browserContextId"`
		} `json:"targetInfos"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("decode getTargets: %v", err)
	}
	var pages int
	for _, ti := range res.TargetInfos {
		if ti.Type != "page" {
			continue
		}
		pages++
		targetID, browserContextID = ti.TargetID, ti.BrowserContextID
	}
	if pages != 1 {
		t.Fatalf("page targets = %d, want exactly 1 (the OTR seeded page): %+v", pages, res.TargetInfos)
	}
	if browserContextID == "" {
		t.Fatal("seeded page has no browserContextId — it is not in an off-the-record context")
	}
	return targetID, browserContextID
}

type namedCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	SameSite string `json:"sameSite"`
}

func assertOTRCookies(ctx context.Context, t *testing.T, client *wsClient, browserContextID string) {
	t.Helper()
	raw, err := client.call(ctx, "", "Storage.getCookies", map[string]any{"browserContextId": browserContextID})
	if err != nil {
		t.Fatalf("Storage.getCookies{browserContextId} over relay: %v", err)
	}
	var got struct {
		Cookies []namedCookie `json:"cookies"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode getCookies: %v", err)
	}
	byName := map[string]namedCookie{}
	for _, c := range got.Cookies {
		byName[c.Name] = c
	}
	if len(got.Cookies) != 2 {
		t.Fatalf("OTR-context getCookies returned %d cookies, want 2: %+v", len(got.Cookies), got.Cookies)
	}

	host := byName["otrproof_hostonly"]
	if host.Domain != "example.com" {
		t.Errorf("host-only domain = %q, want %q (host-only, no leading dot)", host.Domain, "example.com")
	}
	if !host.Secure {
		t.Errorf("host-only secure = false, want true")
	}
	if host.SameSite != "Strict" {
		t.Errorf("host-only sameSite = %q, want Strict", host.SameSite)
	}

	dom := byName["otrproof_domain"]
	if dom.Domain != ".example.org" {
		t.Errorf("domain cookie domain = %q, want %q (leading dot)", dom.Domain, ".example.org")
	}
	if dom.Secure {
		t.Errorf("domain cookie secure = true, want false")
	}
	if dom.SameSite != "Lax" {
		t.Errorf("domain cookie sameSite = %q, want Lax", dom.SameSite)
	}
}

func cookieCount(ctx context.Context, t *testing.T, client *wsClient, browserContextID string) int {
	t.Helper()
	params := map[string]any{}
	if browserContextID != "" {
		params["browserContextId"] = browserContextID
	}
	raw, err := client.call(ctx, "", "Storage.getCookies", params)
	if err != nil {
		t.Fatalf("Storage.getCookies over relay: %v", err)
	}
	var res struct {
		Cookies []json.RawMessage `json:"cookies"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("decode getCookies: %v", err)
	}
	return len(res.Cookies)
}

// assertClientReachesCookie runs the real attach flow: attach the seeded page,
// drive it to https://example.com offline, and confirm the OTR cookie is
// readable via document.cookie and Network.getCookies.
func assertClientReachesCookie(ctx context.Context, t *testing.T, client *wsClient, pageID string) {
	t.Helper()
	raw, err := client.call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": pageID, "flatten": true})
	if err != nil {
		t.Fatalf("attach seeded page: %v", err)
	}
	var att struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(raw, &att); err != nil {
		t.Fatalf("decode attachToTarget: %v", err)
	}
	sessionID := att.SessionID

	for _, domain := range []string{"Page", "Network", "Fetch"} {
		if _, err := client.call(ctx, sessionID, domain+".enable", nil); err != nil {
			t.Fatalf("%s.enable on seeded page: %v", domain, err)
		}
	}

	loaded := make(chan struct{}, 1)
	stop := make(chan struct{})
	defer close(stop)
	go client.serveEvents(ctx, sessionID, loaded, stop)

	if _, err := client.call(ctx, sessionID, "Page.navigate", map[string]any{"url": "https://example.com/"}); err != nil {
		t.Fatalf("navigate seeded page to example.com: %v", err)
	}
	select {
	case <-loaded:
	case <-time.After(20 * time.Second):
		t.Fatal("seeded page did not load https://example.com within 20s")
	}

	raw, err = client.call(ctx, sessionID, "Runtime.evaluate", map[string]any{
		"expression":    "document.cookie",
		"returnByValue": true,
	})
	if err != nil {
		t.Fatalf("evaluate document.cookie: %v", err)
	}
	var eval struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &eval); err != nil {
		t.Fatalf("decode document.cookie: %v", err)
	}
	if !strings.Contains(eval.Result.Value, "otrproof_hostonly=otrproofval1") {
		t.Errorf("document.cookie on example.com = %q, want it to contain %q", eval.Result.Value, "otrproof_hostonly=otrproofval1")
	}

	raw, err = client.call(ctx, sessionID, "Network.getCookies", map[string]any{"urls": []string{"https://example.com/"}})
	if err != nil {
		t.Fatalf("Network.getCookies: %v", err)
	}
	var netCookies struct {
		Cookies []namedCookie `json:"cookies"`
	}
	if err := json.Unmarshal(raw, &netCookies); err != nil {
		t.Fatalf("decode Network.getCookies: %v", err)
	}
	var found *namedCookie
	for i := range netCookies.Cookies {
		if netCookies.Cookies[i].Name == "otrproof_hostonly" {
			found = &netCookies.Cookies[i]
		}
	}
	if found == nil {
		t.Fatalf("Network.getCookies did not return otrproof_hostonly for example.com: %+v", netCookies.Cookies)
	}
	if found.Value != "otrproofval1" {
		t.Errorf("Network.getCookies otrproof_hostonly value = %q, want %q", found.Value, "otrproofval1")
	}
}

// assertSeededDataNotOnDisk proves the disk side-channel is closed: no file in
// the --user-data-dir carries a seeded cookie name or the localStorage value,
// and the default-context Cookies DB holds none of the seeded cookies.
func assertSeededDataNotOnDisk(t *testing.T, dataDir string) {
	t.Helper()
	sentinels := []string{"otrproof_hostonly", "otrproof_domain", "otrproofls1"}

	err := filepath.WalkDir(dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, rerr := os.ReadFile(path) //nolint:gosec // G304: path is from WalkDir over the test-owned temp dataDir.
		if rerr != nil {
			return nil // a transiently locked Chrome file; the rest still proves the point
		}
		for _, s := range sentinels {
			if containsEncoded(b, s) {
				t.Errorf("seeded value %q found on disk at %s — the OTR context leaked to --user-data-dir", s, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk dataDir: %v", err)
	}

	cookiesDB := filepath.Join(dataDir, "Default", "Cookies")
	if _, statErr := os.Stat(cookiesDB); errors.Is(statErr, fs.ErrNotExist) {
		t.Logf("on-disk proof: %s absent — no persistent cookie store was created", cookiesDB)
		return
	}
	db, err := sql.Open("sqlite", "file:"+cookiesDB+"?mode=ro&immutable=1")
	if err != nil {
		t.Logf("on-disk proof: whole-dir byte scan authoritative; read-only Cookies open skipped: %v", err)
		return
	}
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(context.Background(), "SELECT name FROM cookies")
	if err != nil {
		t.Logf("on-disk proof: whole-dir byte scan authoritative; Cookies query skipped: %v", err)
		return
	}
	defer func() { _ = rows.Close() }()
	var persisted int
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		persisted++
		if name == "otrproof_hostonly" || name == "otrproof_domain" {
			t.Errorf("seeded cookie %q present in on-disk Default/Cookies — disk side-channel is open", name)
		}
	}
	t.Logf("on-disk proof: Default/Cookies holds %d cookie(s), none seeded", persisted)
}

// containsEncoded reports whether b holds needle as ASCII or as UTF-16LE (the
// encoding Chrome's LevelDB uses for localStorage string values).
func containsEncoded(b []byte, needle string) bool {
	if bytes.Contains(b, []byte(needle)) {
		return true
	}
	u16 := make([]byte, 0, len(needle)*2)
	for i := range len(needle) {
		u16 = append(u16, needle[i], 0)
	}
	return bytes.Contains(b, u16)
}

func statusOf(resp *http.Response) any {
	if resp == nil {
		return "<nil response>"
	}
	return resp.StatusCode
}

// wsClient is a concurrency-safe CDP client over the relay ws: a single read
// loop correlates responses by id and fans id-less events to serveEvents.
type wsClient struct {
	c       *websocket.Conn
	writeMu sync.Mutex
	mu      sync.Mutex
	nextID  int
	pending map[int]chan wsResult
	events  chan wsEvent
}

type wsResult struct {
	result json.RawMessage
	err    error
}

type wsEvent struct {
	Method    string
	SessionID string
	Params    json.RawMessage
}

func dialClient(ctx context.Context, url string) (*wsClient, *http.Response, error) {
	c, resp, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		return nil, resp, err
	}
	c.SetReadLimit(-1)
	w := &wsClient{c: c, pending: map[int]chan wsResult{}, events: make(chan wsEvent, 256)}
	go w.readLoop(ctx)
	return w, resp, nil
}

func (w *wsClient) readLoop(ctx context.Context) {
	for {
		_, data, err := w.c.Read(ctx)
		if err != nil {
			w.mu.Lock()
			for id, ch := range w.pending {
				ch <- wsResult{err: err}
				delete(w.pending, id)
			}
			w.mu.Unlock()
			return
		}
		var msg struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
			Method    string          `json:"method"`
			Params    json.RawMessage `json:"params"`
			SessionID string          `json:"sessionId"`
		}
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if msg.ID != 0 {
			w.mu.Lock()
			ch, ok := w.pending[msg.ID]
			delete(w.pending, msg.ID)
			w.mu.Unlock()
			if !ok {
				continue
			}
			if msg.Error != nil {
				ch <- wsResult{err: fmt.Errorf("%s", msg.Error.Message)}
				continue
			}
			ch <- wsResult{result: msg.Result}
			continue
		}
		select {
		case w.events <- wsEvent{Method: msg.Method, SessionID: msg.SessionID, Params: msg.Params}:
		default:
		}
	}
}

func (w *wsClient) call(ctx context.Context, sessionID, method string, params any) (json.RawMessage, error) {
	w.mu.Lock()
	w.nextID++
	id := w.nextID
	ch := make(chan wsResult, 1)
	w.pending[id] = ch
	w.mu.Unlock()

	req := map[string]any{"id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	if sessionID != "" {
		req["sessionId"] = sessionID
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	w.writeMu.Lock()
	err = w.c.Write(ctx, websocket.MessageText, payload)
	w.writeMu.Unlock()
	if err != nil {
		return nil, err
	}
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("cdp %s: %w", method, r.err)
		}
		return r.result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// serveEvents fulfills every intercepted request with an empty offline 200 and
// signals loaded on the page's load event, until stop closes.
func (w *wsClient) serveEvents(ctx context.Context, sessionID string, loaded chan<- struct{}, stop <-chan struct{}) {
	body := base64.StdEncoding.EncodeToString(nil)
	for {
		select {
		case ev := <-w.events:
			if ev.SessionID != sessionID {
				continue
			}
			switch ev.Method {
			case "Fetch.requestPaused":
				var p struct {
					RequestID string `json:"requestId"`
				}
				if err := json.Unmarshal(ev.Params, &p); err != nil {
					continue
				}
				_, _ = w.call(ctx, sessionID, "Fetch.fulfillRequest", map[string]any{
					"requestId":       p.RequestID,
					"responseCode":    200,
					"responseHeaders": []map[string]string{{"name": "Content-Type", "value": "text/html; charset=utf-8"}},
					"body":            body,
				})
			case "Page.loadEventFired":
				select {
				case loaded <- struct{}{}:
				default:
				}
			}
		case <-stop:
			return
		case <-ctx.Done():
			return
		}
	}
}
