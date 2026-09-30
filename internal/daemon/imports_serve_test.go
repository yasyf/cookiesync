package daemon

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	synckit "github.com/yasyf/synckit/rpc"

	"github.com/yasyf/cookiesync/internal/cookie"
)

const importTestSelf = "me@vm"

var (
	importT0 = time.Unix(1_700_000_000, 0)

	importCSRF   = cookie.Cookie{HostKey: "api.third.test", Name: "csrf", Value: "töken", Path: "/v1", ExpiresUTC: 15746918400000000, SameSite: 2}
	importPref   = cookie.Cookie{HostKey: ".other.test", Name: "pref", Value: "dark", Path: "/", ExpiresUTC: 15746918400015625, IsSecure: true}
	importSID    = cookie.Cookie{HostKey: "app.example.test", Name: "sid", Value: "synthetic-session", Path: "/", IsSecure: true, IsHTTPOnly: true, SameSite: 1}
	importOrigin = cookie.OriginStorage{Origin: "https://app.example.test", LocalStorage: []cookie.WebStorageEntry{{Name: "theme", Value: "dark"}}}

	importPlaywrightHosts = []string{"app.example.test", "www.other.test", "api.third.test"}
	importServeKey        = importKey{browser: "chrome", profile: "Default"}
)

const importAppOrigins = `[{"origin":"https://app.example.test","localStorage":[{"name":"theme","value":"dark"}],"sessionStorage":[]}]`

func chromeMicrosAt(t time.Time) cookie.ChromeMicros {
	return cookie.ChromeMicros((t.Unix() + 11_644_473_600) * 1_000_000)
}

func importTestRecord(hosts []string, cookies []cookie.Cookie, origins []cookie.OriginStorage, expiresAt time.Time) importRecord {
	set := make(map[cookie.Host]bool, len(hosts))
	for _, h := range hosts {
		set[cookie.NormalizeHost(h)] = true
	}
	return importRecord{hosts: set, cookies: cookies, origins: origins, expiresAt: expiresAt}
}

func playwrightImportRecord(expiresAt time.Time) importRecord {
	return importTestRecord(importPlaywrightHosts, []cookie.Cookie{importCSRF, importPref, importSID}, []cookie.OriginStorage{importOrigin}, expiresAt)
}

type importServeDaemon struct {
	d       *Daemon
	consent *fakeConsent
	cache   *fakeCache
}

func newImportServeDaemon(t *testing.T, probe Probe) importServeDaemon {
	t.Helper()
	st := stateWith(importTestSelf, "", stateEndpoint(importTestSelf, "chrome", "Default"))
	consent := &fakeConsent{key: cookie.AesKey("0123456789abcdef")}
	c := newFakeCache()
	d := New(consent, c, nil, probe, &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	d.now = func() time.Time { return importT0 }
	return importServeDaemon{d: d, consent: consent, cache: c}
}

func (s importServeDaemon) dispatch(t *testing.T, method string, params map[string]any) *synckit.Response {
	t.Helper()
	return dispatchAs(t, s.d.Dispatcher(), os.Getpid(), method, params)
}

func (s importServeDaemon) assertUntouched(t *testing.T) {
	t.Helper()
	if s.cache.getCalls() != 0 || s.cache.putCalls() != 0 {
		t.Fatalf("cache touched while serving an import: gets=%d puts=%d", s.cache.getCalls(), s.cache.putCalls())
	}
	if len(s.consent.batchCalls) != 0 || len(s.consent.promptedReasons) != 0 || s.consent.unpromptedCalled != 0 || s.consent.biometricCalls.Load() != 0 {
		t.Fatalf("consent evaluated while serving an import: batches=%d prompts=%v unprompted=%d biometric=%d",
			len(s.consent.batchCalls), s.consent.promptedReasons, s.consent.unpromptedCalled, s.consent.biometricCalls.Load())
	}
}

func (s importServeDaemon) recordCount() int {
	s.d.imports.mu.Lock()
	defer s.d.imports.mu.Unlock()
	return len(s.d.imports.records)
}

func servedCookies(t *testing.T, raw json.RawMessage) []cookie.Cookie {
	t.Helper()
	if _, ok := resultMap(t, raw)["warnings"]; ok {
		t.Fatalf("import-served reply carries warnings: %s", raw)
	}
	cookies, err := cookie.UnmarshalCookies(raw)
	if err != nil {
		t.Fatalf("decode cookies %s: %v", raw, err)
	}
	sort.Slice(cookies, func(i, j int) bool { return cookies[i].Name < cookies[j].Name })
	return cookies
}

func servedOrigins(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var reply struct {
		Origins  json.RawMessage `json:"origins"`
		Warnings json.RawMessage `json:"warnings"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil {
		t.Fatalf("decode origins %s: %v", raw, err)
	}
	if reply.Warnings != nil {
		t.Fatalf("import-served reply carries warnings: %s", raw)
	}
	return string(reply.Origins)
}

func assertFallsThrough(t *testing.T, got, control *synckit.Response) {
	t.Helper()
	if got.OK != control.OK || got.Error != control.Error || string(got.Result) != string(control.Result) {
		t.Fatalf("reply diverged from the control daemon:\n got: ok=%v err=%q result=%s\nwant: ok=%v err=%q result=%s",
			got.OK, got.Error, got.Result, control.OK, control.Error, control.Result)
	}
	if control.OK && !strings.Contains(string(control.Result), `"warnings"`) {
		t.Fatalf("control daemon served without warnings: %s", control.Result)
	}
	if !control.OK && control.Error == "" {
		t.Fatalf("control daemon refused with an empty error")
	}
	for _, leak := range []string{"synthetic-session", "theme", "app.example.test"} {
		if strings.Contains(string(got.Result), leak) {
			t.Fatalf("import data %q leaked into a fall-through reply: %s", leak, got.Result)
		}
	}
}

// TestImportServesScopedRequests proves a live import answers every read shape for
// exactly its named hosts — union and browser-scoped cookies, union and
// browser-scoped web storage — without touching the cache or the consent gate.
func TestImportServesScopedRequests(t *testing.T) {
	single := map[string]any{"browser": "chrome", "profile": "Default"}
	tests := []struct {
		name        string
		method      string
		scope       map[string]any
		urls        []any
		wantCookies []cookie.Cookie
		wantOrigins string
	}{
		{"union cookies for app", "get_cookies", nil, []any{"https://app.example.test/"}, []cookie.Cookie{importSID}, ""},
		{"union cookies for www", "get_cookies", nil, []any{"www.other.test"}, []cookie.Cookie{importPref}, ""},
		{"union cookies for both", "get_cookies", nil, []any{"app.example.test", "www.other.test"}, []cookie.Cookie{importPref, importSID}, ""},
		{"single cookies for app", "get_cookies", single, []any{"https://app.example.test/"}, []cookie.Cookie{importSID}, ""},
		{"single cookies for www", "get_cookies", single, []any{"www.other.test"}, []cookie.Cookie{importPref}, ""},
		{"single cookies for both", "get_cookies", single, []any{"app.example.test", "www.other.test"}, []cookie.Cookie{importPref, importSID}, ""},
		{"union storage for app", "get_web_storage", nil, []any{"app.example.test"}, nil, importAppOrigins},
		{"single storage for app", "get_web_storage", single, []any{"app.example.test"}, nil, importAppOrigins},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeMesh(t, importTestSelf)
			s := newImportServeDaemon(t, staticProbe(SessionSnapshot{}))
			s.d.imports.put(importServeKey, playwrightImportRecord(importT0.Add(time.Hour)))
			params := map[string]any{"urls": tt.urls}
			for k, v := range tt.scope {
				params[k] = v
			}
			raw, err := dispatchSelf(t, s.d, tt.method, params)
			if err != nil {
				t.Fatalf("%s: %v", tt.method, err)
			}
			switch tt.method {
			case "get_cookies":
				if got := servedCookies(t, raw); !reflect.DeepEqual(got, tt.wantCookies) {
					t.Fatalf("cookies = %+v, want %+v", got, tt.wantCookies)
				}
			case "get_web_storage":
				if got := servedOrigins(t, raw); got != tt.wantOrigins {
					t.Fatalf("origins = %s, want %s", got, tt.wantOrigins)
				}
			}
			s.assertUntouched(t)
		})
	}
}

// TestImportOutOfScopeFallsThrough proves a request the import does not cover exactly
// — a subdomain, a foreign host, a mix, a peer-driven read, another profile — runs the
// existing consent-gated path byte-for-byte, never a partial import answer.
func TestImportOutOfScopeFallsThrough(t *testing.T) {
	tests := []struct {
		name   string
		method string
		params map[string]any
	}{
		{"union subdomain", "get_cookies", map[string]any{"urls": []any{"sub.app.example.test"}}},
		{"union foreign host", "get_cookies", map[string]any{"urls": []any{"example.com"}}},
		{"union mixed", "get_cookies", map[string]any{"urls": []any{"app.example.test", "example.com"}}},
		{"single peer-driven", "get_cookies", map[string]any{"browser": "chrome", "profile": "Default", "origin": "peer@mac", "urls": []any{"app.example.test"}}},
		{"union peer-driven", "get_cookies", map[string]any{"origin": "peer@mac", "urls": []any{"app.example.test"}}},
		{"single other profile", "get_cookies", map[string]any{"browser": "chrome", "profile": "Profile 1", "urls": []any{"app.example.test"}}},
		{"storage union subdomain", "get_web_storage", map[string]any{"urls": []any{"sub.app.example.test"}}},
		{"storage union mixed", "get_web_storage", map[string]any{"urls": []any{"app.example.test", "example.com"}}},
		{"storage single other profile", "get_web_storage", map[string]any{"browser": "chrome", "profile": "Profile 1", "urls": []any{"app.example.test"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeMesh(t, importTestSelf)
			imported := newImportServeDaemon(t, staticProbe(SessionSnapshot{}))
			imported.d.imports.put(importServeKey, playwrightImportRecord(importT0.Add(time.Hour)))
			control := newImportServeDaemon(t, staticProbe(SessionSnapshot{}))
			assertFallsThrough(t, imported.dispatch(t, tt.method, tt.params), control.dispatch(t, tt.method, tt.params))
		})
	}
}

// TestImportHostAliasesFallThrough proves a request whose URL merely looks like a
// named host — a fragment hiding userinfo, a neighbouring IPv6 literal — is not
// covered, while the host the import actually names is served.
func TestImportHostAliasesFallThrough(t *testing.T) {
	tests := []struct {
		name    string
		hosts   []string
		hostKey cookie.HostKey
		served  []any
		aliased []any
	}{
		{"fragment hiding userinfo", []string{"app.example.test"}, "app.example.test", []any{"https://app.example.test/"}, []any{"https://evil.test#@app.example.test"}},
		{"neighbouring IPv6 literal", []string{"[2001:db8::1]"}, "[2001:db8::1]", []any{"https://[2001:db8::1]:8443/p"}, []any{"https://[2001:db8::2]"}},
		{"backslash scheme", []string{"app.example.test"}, "app.example.test", []any{"https://app.example.test/"}, []any{`evil.test\https://app.example.test`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeMesh(t, importTestSelf)
			sid := cookie.Cookie{HostKey: tt.hostKey, Name: "sid", Value: "synthetic-session", Path: "/", IsSecure: true}
			imported := newImportServeDaemon(t, staticProbe(SessionSnapshot{}))
			imported.d.imports.put(importServeKey, importTestRecord(tt.hosts, []cookie.Cookie{sid}, nil, importT0.Add(time.Hour)))

			raw, err := dispatchSelf(t, imported.d, "get_cookies", map[string]any{"urls": tt.served})
			if err != nil {
				t.Fatalf("get_cookies for the named host: %v", err)
			}
			if got := servedCookies(t, raw); !reflect.DeepEqual(got, []cookie.Cookie{sid}) {
				t.Fatalf("cookies for the named host = %+v, want %+v", got, []cookie.Cookie{sid})
			}
			imported.assertUntouched(t)

			control := newImportServeDaemon(t, staticProbe(SessionSnapshot{}))
			params := map[string]any{"urls": tt.aliased}
			assertFallsThrough(t, imported.dispatch(t, "get_cookies", params), control.dispatch(t, "get_cookies", params))
		})
	}
}

// TestImportExpiryFallsThrough pins the clock: an expired cookie inside a live record
// is dropped at read time, and the record itself vanishes the instant its TTL lapses.
func TestImportExpiryFallsThrough(t *testing.T) {
	fakeMesh(t, importTestSelf)
	s := newImportServeDaemon(t, staticProbe(SessionSnapshot{}))
	clock := importT0
	s.d.now = func() time.Time { return clock }
	stale := cookie.Cookie{HostKey: "app.example.test", Name: "stale", Value: "old", Path: "/", ExpiresUTC: chromeMicrosAt(importT0.Add(30 * time.Second))}
	s.d.imports.put(importServeKey, importTestRecord(importPlaywrightHosts,
		[]cookie.Cookie{importCSRF, importPref, importSID, stale}, []cookie.OriginStorage{importOrigin}, importT0.Add(60*time.Second)))
	control := newImportServeDaemon(t, staticProbe(SessionSnapshot{}))
	params := map[string]any{"urls": []any{"app.example.test"}}

	clock = importT0.Add(59 * time.Second)
	raw, err := dispatchSelf(t, s.d, "get_cookies", params)
	if err != nil {
		t.Fatalf("get_cookies one second before expiry: %v", err)
	}
	if got := servedCookies(t, raw); !reflect.DeepEqual(got, []cookie.Cookie{importSID}) {
		t.Fatalf("cookies = %+v, want only sid (stale dropped)", got)
	}
	s.assertUntouched(t)

	clock = importT0.Add(60 * time.Second)
	assertFallsThrough(t, s.dispatch(t, "get_cookies", params), control.dispatch(t, "get_cookies", params))
	if got := s.recordCount(); got != 0 {
		t.Fatalf("records after expiry = %d, want 0", got)
	}
}

// TestImportReplacementServesOnlyTheNewRecord proves a put replaces the whole record: a
// webstorage-only import answers get_cookies with an empty set (never the old cookies)
// and get_web_storage with exactly its own origins.
func TestImportReplacementServesOnlyTheNewRecord(t *testing.T) {
	fakeMesh(t, importTestSelf)
	s := newImportServeDaemon(t, staticProbe(SessionSnapshot{}))
	s.d.imports.put(importServeKey, playwrightImportRecord(importT0.Add(time.Hour)))
	s.d.imports.put(importServeKey, importTestRecord([]string{"app.example.test"}, nil, []cookie.OriginStorage{
		{Origin: "https://app.example.test", LocalStorage: []cookie.WebStorageEntry{{Name: "theme", Value: "dark"}}, SessionStorage: []cookie.WebStorageEntry{{Name: "draft", Value: "synthetic"}}},
		{Origin: "https://app.example.test:8443", LocalStorage: []cookie.WebStorageEntry{}, SessionStorage: []cookie.WebStorageEntry{{Name: "tab", Value: "1"}}},
	}, importT0.Add(time.Hour)))
	params := map[string]any{"urls": []any{"app.example.test"}}

	raw, err := dispatchSelf(t, s.d, "get_cookies", params)
	if err != nil {
		t.Fatalf("get_cookies over a webstorage-only record: %v", err)
	}
	if got := servedCookies(t, raw); len(got) != 0 || !strings.Contains(string(raw), `"cookies":[]`) {
		t.Fatalf("cookies = %+v (%s), want an empty set", got, raw)
	}
	raw, err = dispatchSelf(t, s.d, "get_web_storage", params)
	if err != nil {
		t.Fatalf("get_web_storage over a webstorage-only record: %v", err)
	}
	want := `[{"origin":"https://app.example.test","localStorage":[{"name":"theme","value":"dark"}],"sessionStorage":[{"name":"draft","value":"synthetic"}]},` +
		`{"origin":"https://app.example.test:8443","localStorage":[],"sessionStorage":[{"name":"tab","value":"1"}]}]`
	if got := servedOrigins(t, raw); got != want {
		t.Fatalf("origins = %s, want %s", got, want)
	}
	s.assertUntouched(t)
}

// TestImportUnionAcrossTwoRecords proves the browser-less union folds only the records
// naming each host, newest cookie winning and the lowest key's origins folding first.
func TestImportUnionAcrossTwoRecords(t *testing.T) {
	fakeMesh(t, importTestSelf)
	s := newImportServeDaemon(t, staticProbe(SessionSnapshot{}))
	sidOne := cookie.Cookie{HostKey: "app.example.test", Name: "sid", Value: "one", Path: "/", LastUpdateUTC: 1}
	sidTwo := cookie.Cookie{HostKey: "app.example.test", Name: "sid", Value: "two", Path: "/", LastUpdateUTC: 2}
	shared := cookie.Cookie{HostKey: ".example.test", Name: "shared", Value: "both", Path: "/"}
	key := cookie.Cookie{HostKey: "api.example.test", Name: "key", Value: "k", Path: "/"}
	s.d.imports.put(importServeKey, importTestRecord([]string{"app.example.test"}, []cookie.Cookie{sidOne, shared},
		[]cookie.OriginStorage{{Origin: "https://app.example.test", LocalStorage: []cookie.WebStorageEntry{{Name: "theme", Value: "one"}}}}, importT0.Add(time.Hour)))
	s.d.imports.put(importKey{browser: "chrome", profile: "Profile 1"}, importTestRecord([]string{"app.example.test", "api.example.test"}, []cookie.Cookie{sidTwo, key},
		[]cookie.OriginStorage{{Origin: "https://app.example.test", LocalStorage: []cookie.WebStorageEntry{{Name: "theme", Value: "two"}}}}, importT0.Add(time.Hour)))

	raw, err := dispatchSelf(t, s.d, "get_cookies", map[string]any{"urls": []any{"app.example.test"}})
	if err != nil {
		t.Fatalf("union get_cookies for app: %v", err)
	}
	if got, want := servedCookies(t, raw), []cookie.Cookie{shared, sidTwo}; !reflect.DeepEqual(got, want) {
		t.Fatalf("cookies for app = %+v, want %+v", got, want)
	}
	raw, err = dispatchSelf(t, s.d, "get_web_storage", map[string]any{"urls": []any{"app.example.test"}})
	if err != nil {
		t.Fatalf("union get_web_storage for app: %v", err)
	}
	wantOrigins := `[{"origin":"https://app.example.test","localStorage":[{"name":"theme","value":"one"}],"sessionStorage":[]}]`
	if got := servedOrigins(t, raw); got != wantOrigins {
		t.Fatalf("origins for app = %s, want %s", got, wantOrigins)
	}
	raw, err = dispatchSelf(t, s.d, "get_cookies", map[string]any{"urls": []any{"api.example.test"}})
	if err != nil {
		t.Fatalf("union get_cookies for api: %v", err)
	}
	if got, want := servedCookies(t, raw), []cookie.Cookie{key}; !reflect.DeepEqual(got, want) {
		t.Fatalf("cookies for api = %+v, want %+v (shared applies but its record does not name api)", got, want)
	}
	s.assertUntouched(t)

	control := newImportServeDaemon(t, staticProbe(SessionSnapshot{}))
	mixed := map[string]any{"urls": []any{"app.example.test", "nope.test"}}
	assertFallsThrough(t, s.dispatch(t, "get_cookies", mixed), control.dispatch(t, "get_cookies", mixed))
}

// TestImportIsVMWide proves a record is not bound to the principal that stored it: any
// same-UID requestor reads it.
func TestImportIsVMWide(t *testing.T) {
	fakeMesh(t, importTestSelf)
	s := newImportServeDaemon(t, staticProbe(SessionSnapshot{}))
	s.d.imports.put(importServeKey, playwrightImportRecord(importT0.Add(time.Hour)))
	raw, err := dispatchSelf(t, s.d, "get_cookies", map[string]any{"urls": []any{"app.example.test"}, "requestor": "b"})
	if err != nil {
		t.Fatalf("get_cookies as requestor b: %v", err)
	}
	if got := servedCookies(t, raw); !reflect.DeepEqual(got, []cookie.Cookie{importSID}) {
		t.Fatalf("cookies = %+v, want sid", got)
	}
	s.assertUntouched(t)
}

// TestBridgeSeedPrefersALiveImport drives bridgeSeed directly: an imported target
// seeds from memory with no tap and a lease capped at its remaining TTL, or is refused
// once the import lapsed; a target resolved on disk taps and reads the profile.
func TestBridgeSeedPrefersALiveImport(t *testing.T) {
	stale := cookie.Cookie{HostKey: "app.example.test", Name: "stale", Value: "old", Path: "/", ExpiresUTC: chromeMicrosAt(importT0.Add(-time.Second))}
	imported := []cookie.Cookie{importCSRF, importPref, importSID, stale}
	fromImport := cookie.StorageState{Cookies: []cookie.Cookie{importCSRF, importPref, importSID}, Origins: []cookie.OriginStorage{importOrigin}}
	fromProfile := cookie.StorageState{Cookies: []cookie.Cookie{{HostKey: "profile.test", Name: "local", Value: "v", Path: "/"}}}
	tests := []struct {
		name       string
		expiresIn  time.Duration
		imported   bool
		wantState  cookie.StorageState
		wantCounts cookie.SeedCounts
		wantTTL    time.Duration
		wantExpiry time.Time
		wantErr    string
		wantTaps   int32
		wantReads  int32
	}{
		{"live import seeds without a tap", time.Minute, true, fromImport, cookie.SeedCounts{Attempted: 4, Expired: 1}, time.Minute, importT0.Add(time.Minute), "", 0, 0},
		{"lease caps a longer import", time.Hour, true, fromImport, cookie.SeedCounts{Attempted: 4, Expired: 1}, 10 * time.Minute, importT0.Add(time.Hour), "", 0, 0},
		{"no import taps and reads the profile", 0, false, fromProfile, cookie.SeedCounts{Attempted: 1}, 10 * time.Minute, time.Time{}, "", 1, 1},
		{"a target resolved on disk ignores a live import", time.Minute, false, fromProfile, cookie.SeedCounts{Attempted: 1}, 10 * time.Minute, time.Time{}, "", 1, 1},
		{"an import that lapsed after resolution is refused", 0, true, cookie.StorageState{}, cookie.SeedCounts{}, 0, time.Time{}, "import for chrome/Default expired before bridge startup", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeMesh(t, importTestSelf)
			s := newImportServeDaemon(t, staticProbe(liveSession(currentUser(t))))
			var reads atomic.Int32
			s.d.seedSource = func(context.Context, cookie.Browser, string, cookie.AesKey) (cookie.StorageState, cookie.SeedCounts, error) {
				reads.Add(1)
				return fromProfile, cookie.SeedCounts{Attempted: len(fromProfile.Cookies)}, nil
			}
			if tt.expiresIn != 0 {
				s.d.imports.put(importServeKey, importTestRecord(importPlaywrightHosts, imported, []cookie.OriginStorage{importOrigin}, importT0.Add(tt.expiresIn)))
			}
			chrome, err := cookie.Lookup(cookie.BrowserName("chrome"))
			if err != nil {
				t.Fatalf("lookup chrome: %v", err)
			}
			state, counts, ttl, expiry, err := s.d.bridgeSeed(context.Background(), "req:a", "chrome", "Default", chrome, "", tt.imported)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("bridgeSeed error = %v, want %q", err, tt.wantErr)
				}
				if got := s.consent.biometricCalls.Load() + reads.Load(); got != 0 {
					t.Fatalf("taps+reads after the refusal = %d, want 0", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("bridgeSeed: %v", err)
			}
			if !reflect.DeepEqual(state, tt.wantState) {
				t.Fatalf("state = %+v, want %+v", state, tt.wantState)
			}
			if counts != tt.wantCounts {
				t.Fatalf("counts = %+v, want %+v", counts, tt.wantCounts)
			}
			if ttl != tt.wantTTL {
				t.Fatalf("ttl = %v, want %v", ttl, tt.wantTTL)
			}
			if !expiry.Equal(tt.wantExpiry) {
				t.Fatalf("import expiry = %v, want %v", expiry, tt.wantExpiry)
			}
			if got := s.consent.biometricCalls.Load(); got != tt.wantTaps {
				t.Fatalf("ObtainKeyBiometric calls = %d, want %d", got, tt.wantTaps)
			}
			if got := reads.Load(); got != tt.wantReads {
				t.Fatalf("seedSource calls = %d, want %d", got, tt.wantReads)
			}
		})
	}
}
