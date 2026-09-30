package daemon

import (
	"maps"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
)

func TestNewImportRecordNeverWidens(t *testing.T) {
	expiresAt := time.Unix(1_700_000_000, 0)
	hostOnly := cookie.Cookie{HostKey: "api.third.test", Name: "csrf", Value: "töken", Path: "/v1", SameSite: 2}
	domain := cookie.Cookie{HostKey: ".example.test", Name: "pref", Value: "dark", Path: "/", IsSecure: true}
	theme := []cookie.WebStorageEntry{{Name: "theme", Value: "dark"}}
	tests := []struct {
		name      string
		hosts     []string
		parsed    cookie.StorageState
		wantHosts []string
		wantErr   string
	}{
		{
			"a host-only cookie sent to no named host refuses the import",
			[]string{"app.example.test"},
			cookie.StorageState{Cookies: []cookie.Cookie{hostOnly}},
			nil,
			`import refused: cookie "csrf" for api.third.test is sent to none of the named hosts`,
		},
		{
			"a domain cookie sent to a named subdomain is in scope",
			[]string{"app.example.test"},
			cookie.StorageState{Cookies: []cookie.Cookie{domain}},
			[]string{"app.example.test"},
			"",
		},
		{
			"a domain cookie sent to its named base host is in scope",
			[]string{"example.test"},
			cookie.StorageState{Cookies: []cookie.Cookie{domain}},
			[]string{"example.test"},
			"",
		},
		{
			"the first out-of-scope cookie in document order names the refusal",
			[]string{"example.test"},
			cookie.StorageState{Cookies: []cookie.Cookie{domain, hostOnly}},
			nil,
			`import refused: cookie "csrf" for api.third.test is sent to none of the named hosts`,
		},
		{
			"an origin with a port is scoped by its host",
			[]string{"app.example.test"},
			cookie.StorageState{Origins: []cookie.OriginStorage{{Origin: "https://app.example.test:8443", LocalStorage: theme}}},
			[]string{"app.example.test"},
			"",
		},
		{
			"an origin outside the named hosts refuses the import",
			[]string{"app.example.test"},
			cookie.StorageState{Origins: []cookie.OriginStorage{{Origin: "https://evil.test", LocalStorage: theme}}},
			nil,
			"import refused: origin https://evil.test is not a named host",
		},
		{
			"a named origin is normalized to its bare lowercase host",
			[]string{"https://App.Example.Test/"},
			cookie.StorageState{},
			[]string{"app.example.test"},
			"",
		},
		{
			"a named origin with a port is scoped by its host",
			[]string{"https://app.example.test:8443"},
			cookie.StorageState{},
			[]string{"app.example.test"},
			"",
		},
		{
			"a named IPv6 literal keeps its brackets",
			[]string{"https://[2001:DB8::1]:8443"},
			cookie.StorageState{Cookies: []cookie.Cookie{{HostKey: "[2001:db8::1]", Name: "v6", Value: "x", Path: "/"}}},
			[]string{"[2001:db8::1]"},
			"",
		},
		{
			"a named host naming nothing refuses the import",
			[]string{"https://"},
			cookie.StorageState{},
			nil,
			`import host "https://" must be a bare host or an origin`,
		},
		{
			"a named host with a path refuses the import",
			[]string{"https://app.example.test/x"},
			cookie.StorageState{},
			nil,
			`import host "https://app.example.test/x" must be a bare host or an origin`,
		},
		{
			"a named host with userinfo refuses the import",
			[]string{"https://alice@app.example.test"},
			cookie.StorageState{},
			nil,
			`import host "https://alice@app.example.test" must be a bare host or an origin`,
		},
		{
			"a named host with a query refuses the import",
			[]string{"app.example.test?x=1"},
			cookie.StorageState{},
			nil,
			`import host "app.example.test?x=1" must be a bare host or an origin`,
		},
		{
			"a named host hiding a fragment alias refuses the import",
			[]string{"https://evil.test#@app.example.test"},
			cookie.StorageState{},
			nil,
			`import host "https://evil.test#@app.example.test" must be a bare host or an origin`,
		},
		{
			"a named host hiding a backslash alias refuses the import",
			[]string{`https://evil.com\@app.example.test`},
			cookie.StorageState{},
			nil,
			`import host "https://evil.com\\@app.example.test" must be a bare host or an origin`,
		},
		{
			"a named host with an unclosed IPv6 literal refuses the import",
			[]string{"[2001:db8::1"},
			cookie.StorageState{},
			nil,
			`import host "[2001:db8::1" must be a bare host or an origin`,
		},
		{
			"an origin with a path refuses the import",
			[]string{"app.example.test"},
			cookie.StorageState{Origins: []cookie.OriginStorage{{Origin: "https://app.example.test/x", LocalStorage: theme}}},
			nil,
			"import refused: origin https://app.example.test/x is not a bare origin",
		},
		{
			"an origin hiding a fragment alias refuses the import",
			[]string{"app.example.test"},
			cookie.StorageState{Origins: []cookie.OriginStorage{{Origin: "https://evil.test#@app.example.test", LocalStorage: theme}}},
			nil,
			"import refused: origin https://evil.test#@app.example.test is not a bare origin",
		},
		{
			"an origin with userinfo refuses the import",
			[]string{"app.example.test"},
			cookie.StorageState{Origins: []cookie.OriginStorage{{Origin: "https://alice@app.example.test", LocalStorage: theme}}},
			nil,
			"import refused: origin https://alice@app.example.test is not a bare origin",
		},
		{
			"an origin for another IPv6 literal refuses the import",
			[]string{"[2001:db8::1]"},
			cookie.StorageState{Origins: []cookie.OriginStorage{{Origin: "https://[2001:db8::2]", LocalStorage: theme}}},
			nil,
			"import refused: origin https://[2001:db8::2] is not a named host",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := newImportRecord(tc.hosts, tc.parsed, expiresAt)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("newImportRecord error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("newImportRecord: %v", err)
			}
			if got := rec.hostList(); !slices.Equal(got, tc.wantHosts) {
				t.Fatalf("hostList = %q, want %q", got, tc.wantHosts)
			}
			if !reflect.DeepEqual(rec.cookies, tc.parsed.Cookies) || !reflect.DeepEqual(rec.origins, tc.parsed.Origins) {
				t.Fatalf("record carries %+v / %+v, want the parsed cookies and origins verbatim", rec.cookies, rec.origins)
			}
			if !rec.expiresAt.Equal(expiresAt) {
				t.Fatalf("expiresAt = %v, want %v", rec.expiresAt, expiresAt)
			}
		})
	}
}

func TestImportTTL(t *testing.T) {
	tests := []struct {
		text    string
		want    time.Duration
		wantErr string
	}{
		{"1s", time.Second, ""},
		{"24h", 24 * time.Hour, ""},
		{"90m", 90 * time.Minute, ""},
		{"0s", 0, "import ttl 0s is outside 1s..24h"},
		{"-1s", 0, "import ttl -1s is outside 1s..24h"},
		{"25h", 0, "import ttl 25h is outside 1s..24h"},
		{"1500ms", 0, `import ttl: invalid duration "1500ms": strconv.Atoi: parsing "1500m": invalid syntax`},
		{"1d", 0, `import ttl: invalid duration unit in "1d" (want h, m, or s)`},
		{"18446744075s", 0, `import ttl: invalid duration "18446744075s": overflows time.Duration`},
	}
	for _, tc := range tests {
		t.Run(tc.text, func(t *testing.T) {
			got, err := ImportTTL(tc.text)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("ImportTTL(%q) error = %v, want %q", tc.text, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("ImportTTL(%q) = %v, %v, want %v", tc.text, got, err, tc.want)
			}
		})
	}
}

func TestImportStoreExpiryAndReplacement(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	defaultKey := importKey{browser: "chrome", profile: "Default"}
	profileKey := importKey{browser: "chrome", profile: "Profile 1"}
	arcKey := importKey{browser: "arc", profile: "Default"}
	first := importRecord{
		hosts:     map[cookie.Host]bool{"app.example.test": true},
		cookies:   []cookie.Cookie{{HostKey: "app.example.test", Name: "sid", Value: "one"}},
		origins:   []cookie.OriginStorage{{Origin: "https://app.example.test", LocalStorage: []cookie.WebStorageEntry{{Name: "theme", Value: "one"}}}},
		expiresAt: now.Add(time.Minute),
	}
	second := importRecord{
		hosts:     map[cookie.Host]bool{"www.other.test": true},
		cookies:   []cookie.Cookie{{HostKey: ".other.test", Name: "pref", Value: "two"}},
		expiresAt: now.Add(2 * time.Minute),
	}
	store := newImportStore()

	store.put(defaultKey, first)
	if got, ok := store.live(defaultKey, now.Add(59*time.Second)); !ok || !reflect.DeepEqual(got, first) {
		t.Fatalf("live one second before expiry = %+v, %v, want the stored record", got, ok)
	}
	if got, ok := store.live(defaultKey, now.Add(time.Minute)); ok {
		t.Fatalf("live at expiry = %+v, want a miss", got)
	}
	if _, present := store.records[defaultKey]; present {
		t.Fatalf("the expired record for %+v is still stored", defaultKey)
	}

	store.put(defaultKey, first)
	store.put(defaultKey, second)
	if got, ok := store.live(defaultKey, now); !ok || !reflect.DeepEqual(got, second) {
		t.Fatalf("live after replacement = %+v, %v, want the second record", got, ok)
	}

	profileRecord := importRecord{hosts: map[cookie.Host]bool{"api.third.test": true}, expiresAt: now.Add(30 * time.Second)}
	store.put(profileKey, profileRecord)
	store.put(arcKey, importRecord{hosts: map[cookie.Host]bool{"arc.test": true}, expiresAt: now.Add(10 * time.Second)})
	store.purge(now.Add(30 * time.Second))
	if got := slices.Collect(maps.Keys(store.records)); !slices.Equal(got, []importKey{defaultKey}) {
		t.Fatalf("keys after purge = %+v, want only %+v", got, defaultKey)
	}

	profileRecord.expiresAt = now.Add(2 * time.Minute)
	store.put(profileKey, profileRecord)
	store.put(arcKey, importRecord{hosts: map[cookie.Host]bool{"arc.test": true}, expiresAt: now})
	if got := store.liveAll(now); !reflect.DeepEqual(got, []importRecord{second, profileRecord}) {
		t.Fatalf("liveAll = %+v, want the Default record then the Profile 1 record", got)
	}
	if _, present := store.records[arcKey]; present {
		t.Fatalf("liveAll kept the expired record for %+v", arcKey)
	}
}

func TestImportStoreHoldsAtMostSixteenRecords(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := func(i int) importKey { return importKey{browser: "chrome", profile: "Profile " + strconv.Itoa(i)} }
	live := importRecord{hosts: map[cookie.Host]bool{"app.example.test": true}, expiresAt: now.Add(time.Hour)}
	replacement := importRecord{hosts: map[cookie.Host]bool{"www.other.test": true}, expiresAt: now.Add(2 * time.Hour)}
	const wantErr = "import refused: 16 records already held"
	store := newImportStore()

	for i := range importMaxRecords {
		if err := store.hold(key(i), live, now); err != nil {
			t.Fatalf("hold record %d: %v", i, err)
		}
	}
	if err := store.hold(key(importMaxRecords), live, now); err == nil || err.Error() != wantErr {
		t.Fatalf("hold of a 17th record error = %v, want %q", err, wantErr)
	}
	if _, present := store.records[key(importMaxRecords)]; present || len(store.records) != importMaxRecords {
		t.Fatalf("store after the refusal holds %d records including the 17th = %v, want the 16 already held", len(store.records), present)
	}

	if err := store.hold(key(0), replacement, now); err != nil {
		t.Fatalf("replacing a held key at the cap: %v", err)
	}
	if got := store.records[key(0)]; !reflect.DeepEqual(got, replacement) {
		t.Fatalf("record after replacement = %+v, want %+v", got, replacement)
	}

	store.put(key(1), importRecord{hosts: map[cookie.Host]bool{"stale.test": true}, expiresAt: now.Add(time.Minute)})
	if err := store.hold(key(importMaxRecords), live, now.Add(time.Minute)); err != nil {
		t.Fatalf("hold once a held record expired: %v", err)
	}
	if _, present := store.records[key(1)]; present || len(store.records) != importMaxRecords {
		t.Fatalf("store after holding past an expiry keeps the expired key = %v with %d records, want it evicted and %d held", present, len(store.records), importMaxRecords)
	}
}
