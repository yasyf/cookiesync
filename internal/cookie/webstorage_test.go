package cookie

import (
	"context"
	"encoding/binary"
	"os"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/syndtr/goleveldb/leveldb"
)

// lsKey builds a Local Storage data key "_<origin>\x00<0x01><name>": the script name is
// stored with the Latin-1 marker, as Chrome writes an ASCII key.
func lsKey(origin, name string) []byte {
	key := append([]byte{lsDataPrefix}, origin...)
	key = append(key, 0x00, strMarkerLatin1)
	return append(key, name...)
}

// latin1Val encodes a value with the 0x01 marker; the test values are ASCII, so their
// UTF-8 bytes are their Latin-1 bytes.
func latin1Val(s string) []byte {
	out := make([]byte, 0, 1+len(s))
	out = append(out, strMarkerLatin1)
	return append(out, s...)
}

// utf16Val encodes a value with the 0x00 marker followed by little-endian UTF-16.
func utf16Val(s string) []byte {
	b := utf16LEBytes(s)
	out := make([]byte, 0, 1+len(b))
	out = append(out, strMarkerUTF16)
	return append(out, b...)
}

// utf16LEBytes is the raw, markerless little-endian UTF-16 encoding a Session Storage
// value carries.
func utf16LEBytes(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[2*i:], u)
	}
	return out
}

func writeLevelDB(t *testing.T, dir string, entries map[string][]byte) {
	t.Helper()
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open leveldb %s: %v", dir, err)
	}
	for k, v := range entries {
		if err := db.Put([]byte(k), v, nil); err != nil {
			_ = db.Close()
			t.Fatalf("put %q: %v", k, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close leveldb: %v", err)
	}
}

// entryMap indexes a run of web-storage entries by name for order-independent assertions.
func entryMap(entries []WebStorageEntry) map[string]string {
	out := map[string]string{}
	for _, e := range entries {
		out[e.Name] = e.Value
	}
	return out
}

const (
	fayeJWT    = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjozMDY1ODB9fQ.sig"
	fayeOrigin = "https://app.findfaye.com"
)

// writeFayeLocalStorage lays down a Local Storage LevelDB with two script values (a
// Latin-1 auth token and a UTF-16 value), an evil.com value for the filter test, a
// partitioned StorageKey row that must be skipped, and two metadata keys that must be
// skipped.
func writeFayeLocalStorage(t *testing.T, root, profile string) Browser {
	t.Helper()
	b := makeBrowser(t, root, profile)
	if err := os.MkdirAll(b.LocalStorageDir(profile), 0o700); err != nil {
		t.Fatalf("mkdir local storage: %v", err)
	}
	writeLevelDB(t, b.LocalStorageDir(profile), map[string][]byte{
		string(lsKey(fayeOrigin, "auth")):                            latin1Val(`{"token":"` + fayeJWT + `"}`),
		string(lsKey(fayeOrigin, "greeting")):                        utf16Val("héllo→世界🎉"),
		string(lsKey("https://evil.com", "stolen")):                  latin1Val("nope"),
		string(lsKey(fayeOrigin+"/^0https://lemire.me", "embedded")): latin1Val("partitioned"),
		"VERSION":            {0x01},
		"META:" + fayeOrigin: {0x08, 0x01},
	})
	return b
}

func TestReadLocalStorageDecodesMarkerForms(t *testing.T) {
	b := writeFayeLocalStorage(t, t.TempDir(), "Default")
	local, err := ReadLocalStorage(context.Background(), b, "Default")
	if err != nil {
		t.Fatalf("ReadLocalStorage: %v", err)
	}

	faye := entryMap(local[fayeOrigin])
	wantAuth := `{"token":"` + fayeJWT + `"}`
	if faye["auth"] != wantAuth {
		t.Fatalf("auth (0x01/Latin-1) = %q, want %q", faye["auth"], wantAuth)
	}
	if faye["greeting"] != "héllo→世界🎉" {
		t.Fatalf("greeting (0x00/UTF-16LE) = %q, want %q", faye["greeting"], "héllo→世界🎉")
	}
	if len(local[fayeOrigin]) != 2 {
		t.Fatalf("faye origin entries = %d, want 2 (metadata keys must be skipped)", len(local[fayeOrigin]))
	}
	if evil := entryMap(local["https://evil.com"]); evil["stolen"] != "nope" {
		t.Fatalf("evil stolen = %q, want %q", evil["stolen"], "nope")
	}
	if _, ok := local["VERSION"]; ok {
		t.Fatal("VERSION metadata key must not surface as an origin")
	}
	if _, ok := local[fayeOrigin+"/^0https://lemire.me"]; ok {
		t.Fatal("partitioned StorageKey origin must not surface")
	}
}

func TestReadLocalStorageMissingDirIsEmpty(t *testing.T) {
	b := makeBrowser(t, t.TempDir(), "Default")
	local, err := ReadLocalStorage(context.Background(), b, "Default")
	if err != nil {
		t.Fatalf("ReadLocalStorage on missing dir: %v", err)
	}
	if len(local) != 0 {
		t.Fatalf("missing Local Storage = %v, want empty", local)
	}
}

// writeFayeSessionStorage lays down a Session Storage LevelDB: two namespaces (an open
// tab per origin) indirecting to their maps, one origin carrying a markerless UTF-16
// value and a 0x01/Latin-1 value, plus a partitioned StorageKey namespace whose map must
// never be read.
func writeFayeSessionStorage(t *testing.T, b Browser, profile string) {
	t.Helper()
	if err := os.MkdirAll(b.SessionStorageDir(profile), 0o700); err != nil {
		t.Fatalf("mkdir session storage: %v", err)
	}
	writeLevelDB(t, b.SessionStorageDir(profile), map[string][]byte{
		"namespace-aaaa_1111-" + fayeOrigin + "/":                    []byte("7"),
		"namespace-bbbb_2222-https://evil.com/":                      []byte("9"),
		"namespace-cccc_3333-" + fayeOrigin + "/^0https://lemire.me": []byte("11"),
		"map-7-replay": utf16LEBytes(`{"id":"r1"}`),
		"map-7-flag":   latin1Val("true"),
		"map-9-loot":   utf16LEBytes("secret"),
		"map-11-glued": latin1Val("must-not-appear"),
		"next-map-id":  []byte("12"),
	})
}

func TestReadSessionStorageIndirection(t *testing.T) {
	b := writeFayeLocalStorage(t, t.TempDir(), "Default")
	writeFayeSessionStorage(t, b, "Default")

	session, err := ReadSessionStorage(context.Background(), b, "Default")
	if err != nil {
		t.Fatalf("ReadSessionStorage: %v", err)
	}
	// Session Storage origins keep their trailing slash (Local Storage does not).
	faye := session[fayeOrigin+"/"]
	want := []WebStorageEntry{{Name: "flag", Value: "true"}, {Name: "replay", Value: `{"id":"r1"}`}}
	if !reflect.DeepEqual(faye, want) {
		t.Fatalf("faye session = %#v, want %#v", faye, want)
	}
	if evil := entryMap(session["https://evil.com/"]); evil["loot"] != "secret" {
		t.Fatalf("evil loot = %q, want %q", evil["loot"], "secret")
	}
	if _, ok := session[fayeOrigin+"/^0https://lemire.me"]; ok {
		t.Fatal("partitioned namespace origin must not surface")
	}
	for origin, entries := range session {
		for _, e := range entries {
			if e.Name == "glued" {
				t.Fatalf("partitioned map entry %q surfaced under %q", e.Name, origin)
			}
		}
	}
}

func TestExtractWebStorageFiltersAndMergesOrigin(t *testing.T) {
	b := writeFayeLocalStorage(t, t.TempDir(), "Default")
	writeFayeSessionStorage(t, b, "Default")

	origins, err := ExtractWebStorage(context.Background(), []string{"https://app.findfaye.com"}, b, "Default")
	if err != nil {
		t.Fatalf("ExtractWebStorage: %v", err)
	}
	// evil.com is rejected; the local (no slash) and session (trailing slash) origins
	// collapse onto one canonical origin.
	if len(origins) != 1 {
		t.Fatalf("origins = %d, want 1 (evil.com filtered, faye merged)", len(origins))
	}
	got := origins[0]
	if got.Origin != fayeOrigin {
		t.Fatalf("origin = %q, want %q (canonical, no trailing slash)", got.Origin, fayeOrigin)
	}
	local := entryMap(got.LocalStorage)
	if local["auth"] != `{"token":"`+fayeJWT+`"}` {
		t.Fatalf("merged localStorage auth = %q", local["auth"])
	}
	if len(got.LocalStorage) != 2 {
		t.Fatalf("localStorage entries = %d, want 2", len(got.LocalStorage))
	}
	sessionNames := make([]string, 0, len(got.SessionStorage))
	for _, e := range got.SessionStorage {
		sessionNames = append(sessionNames, e.Name)
	}
	if !reflect.DeepEqual(sessionNames, []string{"flag", "replay"}) {
		t.Fatalf("sessionStorage names = %v, want [flag replay] (name-sorted)", sessionNames)
	}
	for _, o := range origins {
		if strings.ContainsRune(o.Origin, '^') {
			t.Fatalf("origin %q contains a partition separator", o.Origin)
		}
	}
}

func TestExtractWebStorageRejectsUnmatchedHost(t *testing.T) {
	b := writeFayeLocalStorage(t, t.TempDir(), "Default")
	origins, err := ExtractWebStorage(context.Background(), []string{"https://other.example"}, b, "Default")
	if err != nil {
		t.Fatalf("ExtractWebStorage: %v", err)
	}
	if len(origins) != 0 {
		t.Fatalf("origins = %#v, want none for an unmatched host", origins)
	}
}

func TestParseLocalStorageKeyPartitioned(t *testing.T) {
	cases := []struct {
		name      string
		key       string
		origin    string
		scriptKey string
		ok        bool
	}{
		{"first-party", "_https://app.findfaye.com\x00\x01auth", "https://app.findfaye.com", "auth", true},
		{"top-level-site", "_https://github.com/^0https://lemire.me\x00\x01k", "", "", false},
		{"nonce", "_https://github.com/^13735928559^23405691582\x00\x01k", "", "", false},
		{"ancestor-bit", "_https://github.com/^31\x00\x01k", "", "", false},
		{"opaque-top-level-site", "_https://github.com/^412^234^6https://p.example\x00\x01k", "", "", false},
		{"caret-in-script-key", "_https://app.findfaye.com\x00\x01ca^ret", "https://app.findfaye.com", "ca^ret", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			origin, scriptKey, ok := parseLocalStorageKey([]byte(c.key))
			if origin != c.origin || scriptKey != c.scriptKey || ok != c.ok {
				t.Fatalf("parseLocalStorageKey(%q) = (%q, %q, %v), want (%q, %q, %v)",
					c.key, origin, scriptKey, ok, c.origin, c.scriptKey, c.ok)
			}
		})
	}
}

func TestParseNamespaceOriginPartitioned(t *testing.T) {
	cases := []struct {
		name   string
		key    string
		origin string
		ok     bool
	}{
		{"first-party", "namespace-aaaa_1111-https://app.findfaye.com/", "https://app.findfaye.com/", true},
		{"top-level-site", "namespace-aaaa_1111-https://github.com/^0https://lemire.me", "", false},
		{"nonce", "namespace-aaaa_1111-https://github.com/^1123^2456", "", false},
		{"ancestor-bit", "namespace-aaaa_1111-https://github.com/^31", "", false},
		{"opaque-top-level-site", "namespace-aaaa_1111-https://github.com/^412^234^6https://p.example", "", false},
		{"next-map-id", "next-map-id", "", false},
		{"empty-namespace", "namespace-aaaa_1111-", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			origin, ok := parseNamespaceOrigin(c.key)
			if origin != c.origin || ok != c.ok {
				t.Fatalf("parseNamespaceOrigin(%q) = (%q, %v), want (%q, %v)",
					c.key, origin, ok, c.origin, c.ok)
			}
		})
	}
}
