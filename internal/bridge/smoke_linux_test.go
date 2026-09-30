package bridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/yasyf/cookiesync/internal/cookie"
)

const (
	smokeChromeEnv = "COOKIESYNC_SMOKE_CHROME"
	smokeRunEnv    = "COOKIESYNC_SMOKE_RUN"
)

type smokeProcess struct {
	pid    int
	sid    int
	comm   string
	marked bool
}

func TestSmokeRealChromeSeedsReadsBackAndLeavesNoProcess(t *testing.T) {
	bin := os.Getenv(smokeChromeEnv)
	if bin == "" {
		t.Skipf("skipping: set %s to a Chrome or Chromium binary to run the real-Chrome smoke", smokeChromeEnv)
	}
	marker := smokeMarker(t)
	t.Setenv(smokeRunEnv, marker)

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	proc, err := launchTestChrome(ctx, t, bin, t.TempDir(), false)
	if err != nil {
		t.Fatalf("Launch %s headless: %v", bin, err)
	}
	t.Cleanup(func() { _ = proc.Close() })
	chromePID := proc.Pid()

	conn, err := proc.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
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
		Origins: []cookie.OriginStorage{{
			Origin:       "https://example.com",
			LocalStorage: []cookie.WebStorageEntry{{Name: "otrproof_ls", Value: "otrproofls1"}},
		}},
	}
	report, err := Seed(ctx, conn, state)
	if err != nil {
		t.Fatalf("Seed: %v (chrome stderr: %q)", err, proc.stderr.String())
	}
	if report.CookiesSeeded != 2 || report.CDPRejected != 0 || report.LocalStorageOrigins != 1 {
		t.Fatalf("seed report = %+v, want 2 cookies seeded, 0 rejected, 1 localStorage origin", report)
	}

	srv, err := proc.Serve(ctx, "smoke-bridge-token", "")
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	client, _, err := dialClient(ctx, srv.URL())
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	pageID, browserContextID := soleSeededPage(ctx, t, client)
	assertOTRCookies(ctx, t, client, browserContextID)
	assertClientReachesCookie(ctx, t, client, pageID)
	if got := localStorageItem(ctx, t, client, pageID, "otrproof_ls"); got != "otrproofls1" {
		t.Fatalf("localStorage otrproof_ls on example.com = %q, want %q", got, "otrproofls1")
	}

	running := chromeProcesses(t, chromePID, marker)
	if !containsPID(running, chromePID) {
		t.Fatalf("chrome pid %d missing from its own process set %+v", chromePID, running)
	}
	tracked := proc.handlers.tracked()
	if len(tracked) == 0 {
		t.Errorf("no crashpad handler tracked; chrome did not put %s into a handler's --database, or its handler did not inherit %s", crashpadDatabase(proc.dataDir), launchEnv)
	}
	for _, p := range running {
		if p.sid != chromePID && !slices.Contains(tracked, p.pid) {
			t.Errorf("chrome process %d (%s) runs in session %d, outside the daemonkit-owned session %d, and is not a tracked crashpad handler %v", p.pid, p.comm, p.sid, chromePID, tracked)
		}
	}
	for _, pid := range tracked {
		if !containsPID(running, pid) {
			t.Errorf("tracked crashpad handler %d is not one of this chrome's processes %+v", pid, running)
		}
		environ, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if err != nil {
			t.Fatalf("read tracked crashpad handler %d environment: %v", pid, err)
		}
		if err := verifyLaunchEvidence(environ, proc.handlers.nonce); err != nil {
			t.Errorf("tracked crashpad handler %d did not inherit this launch's environment through crashpad's double fork: %v", pid, err)
		}
	}

	_ = client.c.Close(websocket.StatusNormalClosure, "")
	if err := srv.Close(); err != nil {
		t.Fatalf("close relay: %v", err)
	}
	if err := proc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		survivors := chromeProcesses(t, chromePID, marker)
		if len(survivors) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("chrome processes survived Close: %+v", survivors)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func smokeMarker(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}

func localStorageItem(ctx context.Context, t *testing.T, client *wsClient, pageID, name string) string {
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
	raw, err = client.call(ctx, att.SessionID, "Runtime.evaluate", map[string]any{
		"expression":    "window.localStorage.getItem(" + strconv.Quote(name) + ")",
		"returnByValue": true,
	})
	if err != nil {
		t.Fatalf("read localStorage %q: %v", name, err)
	}
	var eval struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &eval); err != nil {
		t.Fatalf("decode localStorage %q: %v", name, err)
	}
	return eval.Result.Value
}

func chromeProcesses(t *testing.T, chromePID int, marker string) []smokeProcess {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatalf("read /proc: %v", err)
	}
	var found []smokeProcess
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		p, live := readSmokeProcess(t, pid, marker)
		if live && (p.marked || p.sid == chromePID) {
			found = append(found, p)
		}
	}
	return found
}

func readSmokeProcess(t *testing.T, pid int, marker string) (smokeProcess, bool) {
	t.Helper()
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return smokeProcess{}, false
	}
	open, end := bytes.IndexByte(stat, '('), bytes.LastIndexByte(stat, ')')
	fields := strings.Fields(string(stat[end+1:]))
	if fields[0] == "Z" || fields[0] == "X" {
		return smokeProcess{}, false
	}
	sid, err := strconv.Atoi(fields[3])
	if err != nil {
		t.Fatalf("parse session of /proc/%d/stat: %v", pid, err)
	}
	environ, _ := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	marked := bytes.Contains(append(append([]byte{0}, environ...), 0), []byte("\x00"+smokeRunEnv+"="+marker+"\x00"))
	return smokeProcess{pid: pid, sid: sid, comm: string(stat[open+1 : end]), marked: marked}, true
}

func containsPID(processes []smokeProcess, pid int) bool {
	for _, p := range processes {
		if p.pid == pid {
			return true
		}
	}
	return false
}
