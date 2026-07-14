package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/yasyf/cookiesync/internal/bridge"
	"github.com/yasyf/cookiesync/internal/cookie"
)

// TestBridgeOpenReattachClose is the Phase-A live-lifecycle proof over a real
// Chrome: it seeds a fixture StorageState (no real profile read) and drives
// open, re-attach, a wrong-capability probe, close, and closeAllBridges.
func TestBridgeOpenReattachClose(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: launches a real Chrome")
	}
	if _, err := bridge.ResolveHostBinary(); err != nil {
		t.Skipf("skipping: Chrome not installed: %v", err)
	}
	// The daemon validates the profile against the browser's real profiles, so
	// pick one that exists; the fixture below is seeded regardless of its name.
	chrome, err := cookie.Lookup(cookie.BrowserName("chrome"))
	if err != nil {
		t.Fatalf("lookup chrome: %v", err)
	}
	profiles, err := chrome.Profiles()
	if err != nil {
		t.Fatalf("chrome profiles: %v", err)
	}
	if len(profiles) == 0 {
		t.Skip("skipping: no chrome profiles on this host")
	}
	profile := profiles[0].Dir

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	fakeMesh(t, "me@laptop")

	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	st := stateWith("me@laptop", "")
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	t.Cleanup(func() { d.closeAllBridges(context.Background()) })

	fixture := cookie.StorageState{
		Cookies: []cookie.Cookie{{
			HostKey: "example.com", Name: "bridge_probe", Value: "ok", Path: "/",
			IsSecure: true, SameSite: 2, SourceScheme: 2, SourcePort: 443,
		}},
		Origins: []cookie.OriginStorage{{
			Origin:       "https://example.com",
			LocalStorage: []cookie.WebStorageEntry{{Name: "token", Value: "abc"}},
		}},
	}
	var seedCalls atomic.Int32
	d.seedSource = func(_ context.Context, _ cookie.Browser, _ string, _ cookie.AesKey) (cookie.StorageState, int, error) {
		seedCalls.Add(1)
		return fixture, 0, nil
	}

	ctx := context.Background()
	openParams := map[string]any{"browser": "chrome", "profile": profile, "headed": false}

	// (1) open returns a url + capability; the seeded cookie round-trips over ws.
	res1, err := d.handleBridgeOpen(ctx, openParams)
	if err != nil {
		t.Fatalf("bridge_open: %v", err)
	}
	open1 := res1.(map[string]any)
	url1, _ := open1["url"].(string)
	cap1, _ := open1["capability"].(string)
	if url1 == "" || cap1 == "" {
		t.Fatalf("bridge_open missing url/capability: %+v", open1)
	}
	if got := seedCalls.Load(); got != 1 {
		t.Fatalf("seedSource calls = %d, want 1", got)
	}
	if got := consent.biometricCalls.Load(); got != 1 {
		t.Fatalf("ObtainKeyBiometric calls = %d, want 1", got)
	}
	if got := bridgeCount(d); got != 1 {
		t.Fatalf("live sessions = %d, want 1", got)
	}

	client := dialBridge(ctx, t, url1)
	if _, err := client.call(ctx, "", "Target.getTargets", nil); err != nil {
		t.Fatalf("Target.getTargets over relay: %v", err)
	}
	if names := relayCookieNames(ctx, t, client); !contains(names, "bridge_probe") {
		t.Fatalf("relay cookies = %v, want the seeded bridge_probe", names)
	}

	sess1, ok := bridgeSessionFor(d, cap1)
	if !ok {
		t.Fatalf("session for cap1 not registered")
	}
	expiry1 := sess1.expiry

	// (2) re-attach WITH the capability returns the same url, no second tap, no
	// second session, and no lease extension.
	res2, err := d.handleBridgeOpen(ctx, map[string]any{
		"browser": "chrome", "profile": profile, "headed": false, "capability": cap1,
	})
	if err != nil {
		t.Fatalf("bridge_open re-attach: %v", err)
	}
	open2 := res2.(map[string]any)
	if got := open2["url"].(string); got != url1 {
		t.Fatalf("re-attach url = %q, want %q", got, url1)
	}
	if got := open2["capability"].(string); got != cap1 {
		t.Fatalf("re-attach capability = %q, want %q", got, cap1)
	}
	if got := consent.biometricCalls.Load(); got != 1 {
		t.Fatalf("re-attach tapped again: ObtainKeyBiometric calls = %d, want 1", got)
	}
	if got := seedCalls.Load(); got != 1 {
		t.Fatalf("re-attach re-seeded: seedSource calls = %d, want 1", got)
	}
	if got := bridgeCount(d); got != 1 {
		t.Fatalf("re-attach created a second session: live = %d, want 1", got)
	}
	if sess, _ := bridgeSessionFor(d, cap1); sess.expiry != expiry1 {
		t.Fatalf("re-attach extended the lease: expiry %v != %v", sess.expiry, expiry1)
	}

	// (3) a wrong capability leaks nothing: status is empty, and a fresh open
	// without the capability taps again and opens a distinct session.
	stRes, err := d.handleBridgeStatus(ctx, map[string]any{"capability": "not-a-real-capability"})
	if err != nil {
		t.Fatalf("bridge_status wrong cap: %v", err)
	}
	if got := stRes.(map[string]any); len(got) != 0 {
		t.Fatalf("bridge_status for a wrong capability leaked %+v, want empty", got)
	}
	res3, err := d.handleBridgeOpen(ctx, openParams)
	if err != nil {
		t.Fatalf("fresh bridge_open (no cap): %v", err)
	}
	cap3 := res3.(map[string]any)["capability"].(string)
	if cap3 == cap1 {
		t.Fatalf("fresh open reused cap1 %q", cap1)
	}
	if got := consent.biometricCalls.Load(); got != 2 {
		t.Fatalf("fresh open did not tap again: ObtainKeyBiometric calls = %d, want 2", got)
	}
	if got := bridgeCount(d); got != 2 {
		t.Fatalf("live sessions after fresh open = %d, want 2", got)
	}

	// (4) close WITH the capability tears the session down: it leaves the
	// registry and its ws endpoint stops accepting.
	closeRes, err := d.handleBridgeClose(ctx, map[string]any{"capability": cap1})
	if err != nil {
		t.Fatalf("bridge_close: %v", err)
	}
	if !closeRes.(map[string]any)["closed"].(bool) {
		t.Fatalf("bridge_close closed = false, want true")
	}
	if _, ok := bridgeSessionFor(d, cap1); ok {
		t.Fatalf("closed session still in the registry")
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if c, _, err := websocket.Dial(dialCtx, url1, nil); err == nil {
		_ = c.CloseNow()
		t.Fatalf("ws endpoint still accepting after close")
	}

	// (5) closeAllBridges kills everything that remains.
	d.closeAllBridges(ctx)
	if got := bridgeCount(d); got != 0 {
		t.Fatalf("live sessions after closeAllBridges = %d, want 0", got)
	}
}

// TestBridgeFreshOpensDoNotShareSecrets is the C1 proof: two concurrent
// no-capability opens for the SAME requestor+endpoint are never collapsed —
// each runs its own biometric tap and seed and yields a distinct session with a
// distinct token and capability, so no caller can piggyback another's tap or
// steal its secrets. It also spot-checks Fix 2 (the record is on disk the moment
// open returns) and Fix 3 (closeAllBridges drains every session and its relay).
func TestBridgeFreshOpensDoNotShareSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: launches a real Chrome")
	}
	if _, err := bridge.ResolveHostBinary(); err != nil {
		t.Skipf("skipping: Chrome not installed: %v", err)
	}
	chrome, err := cookie.Lookup(cookie.BrowserName("chrome"))
	if err != nil {
		t.Fatalf("lookup chrome: %v", err)
	}
	profiles, err := chrome.Profiles()
	if err != nil {
		t.Fatalf("chrome profiles: %v", err)
	}
	if len(profiles) == 0 {
		t.Skip("skipping: no chrome profiles on this host")
	}
	profile := profiles[0].Dir

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	fakeMesh(t, "me@laptop")

	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	st := stateWith("me@laptop", "")
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	t.Cleanup(func() { d.closeAllBridges(context.Background()) })

	var seedCalls atomic.Int32
	d.seedSource = func(_ context.Context, _ cookie.Browser, _ string, _ cookie.AesKey) (cookie.StorageState, int, error) {
		seedCalls.Add(1)
		return cookie.StorageState{Cookies: []cookie.Cookie{{
			HostKey: "example.com", Name: "bridge_probe", Value: "ok", Path: "/",
			IsSecure: true, SameSite: 2, SourceScheme: 2, SourcePort: 443,
		}}}, 0, nil
	}

	const n = 2
	ctx := context.Background()
	type outcome struct {
		res any
		err error
	}
	results := make([]outcome, n)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// A private param copy per goroutine: same requestor+endpoint (the
			// former collision key), no shared-map write.
			res, err := d.handleBridgeOpen(ctx, map[string]any{"browser": "chrome", "profile": profile, "headed": false})
			results[i] = outcome{res: res, err: err}
		}(i)
	}
	wg.Wait()

	caps, urls, tokens := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, got := range results {
		if got.err != nil {
			t.Fatalf("concurrent open %d: %v", i, got.err)
		}
		open := got.res.(map[string]any)
		capability, _ := open["capability"].(string)
		url, _ := open["url"].(string)
		if capability == "" || url == "" {
			t.Fatalf("open %d missing url/capability: %+v", i, open)
		}
		caps[capability], urls[url] = true, true
		sess, ok := bridgeSessionFor(d, capability)
		if !ok {
			t.Fatalf("open %d session not registered", i)
		}
		tokens[sess.token] = true
		// Fix 2: the crash-durability record is on disk the moment open returns.
		if _, err := os.Stat(filepath.Join(sess.dataDir, bridgeRecordFile)); err != nil {
			t.Fatalf("open %d: session record missing on disk: %v", i, err)
		}
	}
	if len(caps) != n || len(urls) != n || len(tokens) != n {
		t.Fatalf("secret sharing: %d caps, %d urls, %d tokens; want %d distinct each", len(caps), len(urls), len(tokens), n)
	}
	if got := consent.biometricCalls.Load(); got != n {
		t.Fatalf("ObtainKeyBiometric calls = %d, want %d (one tap per fresh open)", got, n)
	}
	if got := seedCalls.Load(); got != n {
		t.Fatalf("seedSource calls = %d, want %d (one seed per fresh open)", got, n)
	}
	if got := bridgeCount(d); got != n {
		t.Fatalf("live sessions = %d, want %d", got, n)
	}

	// Fix 3: closeAllBridges drains every session; each relay refuses a fresh dial.
	d.closeAllBridges(ctx)
	if got := bridgeCount(d); got != 0 {
		t.Fatalf("live sessions after closeAllBridges = %d, want 0", got)
	}
	for url := range urls {
		dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		c, _, err := websocket.Dial(dialCtx, url, nil)
		cancel()
		if err == nil {
			_ = c.CloseNow()
			t.Fatalf("ws endpoint %s still accepting after closeAllBridges", url)
		}
	}
}

// TestReapOrphanBridgeIdentityCheck proves the orphan sweep group-kills only a
// pid whose live identity still matches the record — a recycled pid is spared —
// while always removing the session dir (Fix 5). It stands a harmless `sleep` in
// its own process group in for an orphaned Chrome, so it needs no real browser.
func TestReapOrphanBridgeIdentityCheck(t *testing.T) {
	ctx := context.Background()
	spawn := func() *exec.Cmd {
		c := exec.Command("sleep", "300")
		c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // pid == pgid, like Chrome
		if err := c.Start(); err != nil {
			t.Fatalf("spawn sleep: %v", err)
		}
		return c
	}
	writeRec := func(rec bridgeRecord) string {
		dir := t.TempDir()
		raw, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, bridgeRecordFile), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return filepath.Join(dir, bridgeRecordFile)
	}

	// (1) A stale identity must NOT kill the live pid, but must still remove the dir.
	victim := spawn()
	t.Cleanup(func() { _ = victim.Process.Kill() })
	path1 := writeRec(bridgeRecord{PID: victim.Process.Pid, Start: "Mon Jan 1 00:00:00 2000", Comm: "/not/our/binary"})
	reapOrphanBridge(ctx, path1)
	if _, err := os.Stat(filepath.Dir(path1)); !os.IsNotExist(err) {
		t.Fatalf("mismatched reap must still RemoveAll the dir, stat err = %v", err)
	}
	if syscall.Kill(victim.Process.Pid, 0) != nil {
		t.Fatalf("mismatched reap killed a live pid-reuse victim")
	}

	// (2) A matched identity group-kills the recorded process and removes the dir.
	id, ok, err := probeProcess(ctx, victim.Process.Pid)
	if err != nil || !ok {
		t.Fatalf("probeProcess on a live child: ok=%v err=%v", ok, err)
	}
	path2 := writeRec(bridgeRecord{PID: victim.Process.Pid, Start: id.start, Comm: id.comm})
	reapOrphanBridge(ctx, path2)
	if _, err := os.Stat(filepath.Dir(path2)); !os.IsNotExist(err) {
		t.Fatalf("matched reap must RemoveAll the dir, stat err = %v", err)
	}
	done := make(chan struct{})
	go func() { _ = victim.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("matched reap did not kill the recorded process")
	}

	// (3) A dead pid probes ok=false with no error.
	dead := spawn()
	pid := dead.Process.Pid
	_ = dead.Process.Kill()
	_ = dead.Wait()
	if _, ok, err := probeProcess(ctx, pid); ok || err != nil {
		t.Fatalf("probeProcess on a dead pid: ok=%v err=%v, want false nil", ok, err)
	}
}

func bridgeCount(d *Daemon) int {
	d.bridgeMu.Lock()
	defer d.bridgeMu.Unlock()
	return len(d.bridges)
}

func bridgeSessionFor(d *Daemon, capability string) (*bridgeSession, bool) {
	d.bridgeMu.Lock()
	defer d.bridgeMu.Unlock()
	s, ok := d.bridges[capability]
	return s, ok
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// relayCookieNames reads the OTR context's cookies over the CDP relay: it first
// discovers the sole page target's off-the-record browserContextId, then scopes
// Storage.getCookies to it (the seeded cookies live only there, not the default
// context).
func relayCookieNames(ctx context.Context, t *testing.T, c *wsCDPClient) []string {
	t.Helper()
	raw, err := c.call(ctx, "", "Target.getTargets", nil)
	if err != nil {
		t.Fatalf("Target.getTargets over relay: %v", err)
	}
	var targets struct {
		TargetInfos []struct {
			Type             string `json:"type"`
			BrowserContextID string `json:"browserContextId"`
		} `json:"targetInfos"`
	}
	if err := json.Unmarshal(raw, &targets); err != nil {
		t.Fatalf("decode getTargets: %v", err)
	}
	var browserContextID string
	var pages int
	for _, ti := range targets.TargetInfos {
		if ti.Type != "page" {
			continue
		}
		pages++
		browserContextID = ti.BrowserContextID
	}
	if pages != 1 {
		t.Fatalf("page targets = %d, want exactly 1 (the OTR seeded page): %+v", pages, targets.TargetInfos)
	}
	if browserContextID == "" {
		t.Fatal("seeded page has no browserContextId — it is not off-the-record")
	}

	raw, err = c.call(ctx, "", "Storage.getCookies", map[string]any{"browserContextId": browserContextID})
	if err != nil {
		t.Fatalf("Storage.getCookies over relay: %v", err)
	}
	var got struct {
		Cookies []struct {
			Name string `json:"name"`
		} `json:"cookies"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode getCookies: %v", err)
	}
	names := make([]string, 0, len(got.Cookies))
	for _, ck := range got.Cookies {
		names = append(names, ck.Name)
	}
	return names
}

// wsCDPClient is a minimal single-client CDP websocket peer for the relay.
type wsCDPClient struct {
	c  *websocket.Conn
	id int
}

func dialBridge(ctx context.Context, t *testing.T, url string) *wsCDPClient {
	t.Helper()
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(dialCtx, url, nil)
	if err != nil {
		t.Fatalf("dial relay %s: %v", url, err)
	}
	c.SetReadLimit(-1)
	t.Cleanup(func() { _ = c.CloseNow() })
	return &wsCDPClient{c: c}
}

func (w *wsCDPClient) call(ctx context.Context, sessionID, method string, params any) (json.RawMessage, error) {
	w.id++
	id := w.id
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
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := w.c.Write(callCtx, websocket.MessageText, payload); err != nil {
		return nil, err
	}
	for {
		_, data, err := w.c.Read(callCtx)
		if err != nil {
			return nil, err
		}
		var msg struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(data, &msg); err != nil {
			return nil, err
		}
		if msg.ID != id {
			continue
		}
		if msg.Error != nil {
			return nil, fmt.Errorf("cdp %s: %s", method, msg.Error.Message)
		}
		return msg.Result, nil
	}
}
