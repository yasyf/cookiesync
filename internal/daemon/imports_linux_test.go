//go:build linux

package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
)

var importDefaultKey = importKey{browser: "chrome", profile: "Default"}

func readImportFixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "cookie", "testdata", "import_playwright.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(data)
}

func importDaemon(t *testing.T, now time.Time) (*Daemon, *fakeConsent, *fakeCache) {
	t.Helper()
	self := "me@vm"
	fakeMesh(t, self)
	st := stateWith(self, "", stateEndpoint(self, "chrome", "Default"))
	consent := &fakeConsent{key: cookie.AesKey("0123456789abcdef")}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	d.now = func() time.Time { return now }
	return d, consent, cache
}

func importParams(document string) map[string]any {
	return map[string]any{
		"browser":  "chrome",
		"profile":  "Default",
		"format":   "playwright",
		"ttl":      "2m",
		"hosts":    []any{"app.example.test", "www.other.test", "api.third.test"},
		"document": document,
	}
}

func previousImportRecord(t *testing.T, now time.Time) importRecord {
	t.Helper()
	rec, err := newImportRecord(
		[]string{"app.example.test"},
		cookie.StorageState{Cookies: []cookie.Cookie{{HostKey: "app.example.test", Name: "sid", Value: "previous", Path: "/"}}},
		now.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("previous record: %v", err)
	}
	return rec
}

func assertImportTouchedNothing(t *testing.T, consent *fakeConsent, cache *fakeCache) {
	t.Helper()
	if cache.getCalls() != 0 || cache.putCalls() != 0 {
		t.Fatalf("import touched the key cache: gets=%d puts=%d", cache.getCalls(), cache.putCalls())
	}
	if len(consent.batchCalls) != 0 || len(consent.promptedReasons) != 0 || consent.unpromptedCalled != 0 || consent.biometricCalls.Load() != 0 {
		t.Fatalf("import evaluated consent: batches=%d prompts=%v unprompted=%d biometric=%d",
			len(consent.batchCalls), consent.promptedReasons, consent.unpromptedCalled, consent.biometricCalls.Load())
	}
}

func TestImportRPCStoresTheDocument(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	d, consent, cache := importDaemon(t, now)

	raw, err := dispatchSelf(t, d, "import", importParams(readImportFixture(t)))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	var want map[string]any
	if err := json.Unmarshal([]byte(`{"protocol_version":1,"browser":"chrome","profile":"Default","hosts":["api.third.test","app.example.test","www.other.test"],"cookies":3,"origins":1,"expires_in":120}`), &want); err != nil {
		t.Fatal(err)
	}
	if got := resultMap(t, raw); !reflect.DeepEqual(got, want) {
		t.Fatalf("import reply = %s, want %v", raw, want)
	}

	if len(d.imports.records) != 1 {
		t.Fatalf("store holds %d records, want exactly one", len(d.imports.records))
	}
	rec, ok := d.imports.records[importDefaultKey]
	if !ok {
		t.Fatalf("store holds %v, want a record for %+v", d.imports.records, importDefaultKey)
	}
	if !rec.expiresAt.Equal(now.Add(2 * time.Minute)) {
		t.Fatalf("expiresAt = %v, want now+2m %v", rec.expiresAt, now.Add(2*time.Minute))
	}
	wantHosts := map[cookie.Host]bool{"api.third.test": true, "app.example.test": true, "www.other.test": true}
	if !reflect.DeepEqual(rec.hosts, wantHosts) {
		t.Fatalf("hosts = %v, want %v", rec.hosts, wantHosts)
	}
	names := make([]string, len(rec.cookies))
	for i, c := range rec.cookies {
		names[i] = c.Name
	}
	if !reflect.DeepEqual(names, []string{"csrf", "pref", "sid"}) {
		t.Fatalf("cookie names = %q, want the fixture's three in document order", names)
	}
	if len(rec.origins) != 1 || rec.origins[0].Origin != "https://app.example.test" {
		t.Fatalf("origins = %+v, want the fixture's one origin", rec.origins)
	}
	assertImportTouchedNothing(t, consent, cache)
}

func TestImportRPCStoresAWallClockExpiry(t *testing.T) {
	now := time.Now()
	d, _, _ := importDaemon(t, now)
	if _, err := dispatchSelf(t, d, "import", importParams(readImportFixture(t))); err != nil {
		t.Fatalf("import: %v", err)
	}
	if got, want := d.imports.records[importDefaultKey].expiresAt, now.Add(2*time.Minute).Round(0); got != want {
		t.Fatalf("expiresAt = %v, want the wall-clock %v", got, want)
	}
}

func TestImportRPCRefusesASeventeenthRecord(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	d, consent, cache := importDaemon(t, now)
	held := map[importKey]importRecord{}
	for i := range importMaxRecords {
		key := importKey{browser: "chrome", profile: "Profile " + strconv.Itoa(i)}
		held[key] = previousImportRecord(t, now)
		d.imports.put(key, held[key])
	}

	_, err := dispatchSelf(t, d, "import", importParams(readImportFixture(t)))
	if want := "import refused: 16 records already held"; err == nil || err.Error() != want {
		t.Fatalf("import error = %v, want %q", err, want)
	}
	if !reflect.DeepEqual(d.imports.records, held) {
		t.Fatalf("store after the refusal = %+v, want only the 16 records already held", d.imports.records)
	}
	assertImportTouchedNothing(t, consent, cache)
}

func TestImportRPCRefusesAndKeepsThePreviousRecord(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fixture := readImportFixture(t)
	tests := []struct {
		name    string
		mutate  func(params map[string]any)
		wantErr string
	}{
		{
			"a cookie sent past the named hosts",
			func(p map[string]any) { p["hosts"] = []any{"app.example.test"} },
			`import refused: cookie "csrf" for api.third.test is sent to none of the named hosts`,
		},
		{"a ttl above the cap", func(p map[string]any) { p["ttl"] = "25h" }, "import ttl 25h is outside 1s..24h"},
		{"a zero ttl", func(p map[string]any) { p["ttl"] = "0s" }, "import ttl 0s is outside 1s..24h"},
		{"a browser outside the local registry", func(p map[string]any) { p["browser"] = "arc" }, `unknown browser "arc"`},
		{"an empty profile", func(p map[string]any) { p["profile"] = "" }, "import requires a non-empty profile"},
		{"the header format", func(p map[string]any) { p["format"] = "header" }, `unknown import format "header": want playwright or webstorage`},
		{"no hosts", func(p map[string]any) { delete(p, "hosts") }, "import requires non-empty hosts"},
		{"an empty host", func(p map[string]any) { p["hosts"] = []any{""} }, "hosts[0] is string, want non-empty string"},
		{"a document outside the format's grammar", func(p map[string]any) { p["document"] = `{"origins": []}` }, `parse playwright document: missing "cookies"`},
		{"a missing document", func(p map[string]any) { delete(p, "document") }, `missing required param "document"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, consent, cache := importDaemon(t, now)
			previous := previousImportRecord(t, now)
			d.imports.put(importDefaultKey, previous)
			params := importParams(fixture)
			tc.mutate(params)

			_, err := dispatchSelf(t, d, "import", params)
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("import error = %v, want %q", err, tc.wantErr)
			}
			if !reflect.DeepEqual(d.imports.records, map[importKey]importRecord{importDefaultKey: previous}) {
				t.Fatalf("store after the refusal = %+v, want only the previous record", d.imports.records)
			}
			assertImportTouchedNothing(t, consent, cache)
		})
	}
}

func TestUnderivableRequestorRefusedBeforeImport(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fixture := readImportFixture(t)
	for _, peer := range []struct {
		name string
		pid  int
	}{
		{"peer outside the pid namespace", 0},
		{"exited peer", exitedPID(t)},
	} {
		t.Run(peer.name, func(t *testing.T) {
			d, consent, cache := importDaemon(t, now)
			previous := previousImportRecord(t, now)
			d.imports.put(importDefaultKey, previous)

			resp := dispatchAs(t, d.Dispatcher(), peer.pid, "import", importParams(fixture))
			if resp.OK {
				t.Fatalf("import served %s, want a refusal", resp.Result)
			}
			if !strings.HasPrefix(resp.Error, "cannot derive a requestor for socket peer pid "+strconv.Itoa(peer.pid)+" (") || !strings.HasSuffix(resp.Error, requestorHint) {
				t.Fatalf("import error = %q, want the requestor refusal", resp.Error)
			}
			if !reflect.DeepEqual(d.imports.records, map[importKey]importRecord{importDefaultKey: previous}) {
				t.Fatalf("store after the refusal = %+v, want only the previous record", d.imports.records)
			}
			assertImportTouchedNothing(t, consent, cache)
		})
	}
}
