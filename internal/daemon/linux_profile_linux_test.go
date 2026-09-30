package daemon

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1" //nolint:gosec // G505: Chromium's PBKDF2 derivation uses HMAC-SHA1.
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/syndtr/goleveldb/leveldb"

	"github.com/yasyf/cookiesync/internal/cookie"
)

const linuxMetaSchema = `
CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
INSERT INTO meta VALUES ('version', '24'), ('last_compatible_version', '24');
`

type linuxRow struct {
	host, name, value string
	secure, httpOnly  bool
	sameSite          int
}

// sealLinuxV10 encrypts value the way Linux Chromium does without a keyring,
// independently of the cookie package: PBKDF2-SHA1("peanuts", "saltysalt", 1)
// AES-128-CBC with a 16-space IV, and the SHA-256(host_key) prefix a v24 store carries.
func sealLinuxV10(t *testing.T, host, value string) []byte {
	t.Helper()
	key, err := pbkdf2.Key(sha1.New, "peanuts", []byte("saltysalt"), 1, 16)
	if err != nil {
		t.Fatalf("pbkdf2: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	hash := sha256.Sum256([]byte(host))
	plain := append(hash[:], value...)
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	plain = append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, bytes.Repeat([]byte{' '}, aes.BlockSize)).CryptBlocks(out, plain)
	return append([]byte("v10"), out...)
}

func writeLinuxCookieStore(t *testing.T, browser cookie.Browser, profile string, rows []linuxRow) {
	t.Helper()
	if err := os.MkdirAll(browser.ProfileDir(profile), 0o700); err != nil {
		t.Fatalf("mkdir profile: %v", err)
	}
	db, err := sql.Open("sqlite", browser.CookiesDB(profile))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(v24Schema + linuxMetaSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	for i, r := range rows {
		_, err := db.Exec(
			`INSERT INTO cookies VALUES (?, ?, '', ?, '', ?, '/', 0, ?, ?, ?, 0, 0, 1, ?, 2, 443, ?, 0, 0)`,
			13_350_000_000_000_000+i, r.host, r.name, sealLinuxV10(t, r.host, r.value),
			r.secure, r.httpOnly, 13_350_000_000_000_000+i, r.sameSite, 13_350_000_000_000_000+i,
		)
		if err != nil {
			t.Fatalf("insert %s: %v", r.name, err)
		}
	}
}

func writeLinuxLevelDB(t *testing.T, dir string, entries map[string][]byte) {
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

func utf16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[2*i:], u)
	}
	return out
}

func writeLinuxWebStorage(t *testing.T, browser cookie.Browser, profile string) {
	t.Helper()
	writeLinuxLevelDB(t, browser.LocalStorageDir(profile), map[string][]byte{
		"_https://app.example.test\x00\x01theme": []byte("\x01dark"),
		"_https://other.test\x00\x01stolen":      []byte("\x01nope"),
		"VERSION":                                {0x01},
		"META:https://app.example.test":          {0x08, 0x01},
	})
	writeLinuxLevelDB(t, browser.SessionStorageDir(profile), map[string][]byte{
		"namespace-aaaa_1111-https://app.example.test/": []byte("7"),
		"namespace-bbbb_2222-https://other.test/":       []byte("9"),
		"map-7-draft": utf16LE("hi"),
		"map-9-loot":  utf16LE("secret"),
		"next-map-id": []byte("10"),
	})
}

// TestLinuxChromiumProfileRendersEveryConsumerFormat drives a synthetic Linux Chromium
// profile (v10 rows in a meta-24 store, Local and Session Storage LevelDBs) through the
// in-process daemon with a warm key and a consent double, then renders the replies the
// way the cookies command does and pins the exact bytes of each consumer format.
func TestLinuxChromiumProfileRendersEveryConsumerFormat(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("COOKIESYNC_CONFIG_DIR", filepath.Join(home, ".config", "cookiesync"))
	browser, err := cookie.Lookup("chromium")
	if err != nil {
		t.Fatalf("lookup chromium: %v", err)
	}
	if want := filepath.Join(home, ".config", "chromium"); browser.DataRoot != want {
		t.Fatalf("chromium data root = %q, want %q", browser.DataRoot, want)
	}
	writeLinuxCookieStore(t, browser, "Default", []linuxRow{
		{host: "app.example.test", name: "sid", value: "s3ss10n", secure: true, httpOnly: true, sameSite: 1},
		{host: "other.test", name: "tok", value: "elsewhere", secure: true, sameSite: 2},
	})
	writeLinuxWebStorage(t, browser, "Default")

	fakeMesh(t, "me@vm")
	st := stateWith("me@vm", "")
	cache := newFakeCache()
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	_, _ = cache.Put(ctx, endpointID("me@vm", "chromium", "Default"), []byte(key), 0)
	consent := &fakeConsent{}
	d := New(consent, cache, nil, staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	d.grant("local", []cookie.BrowserName{"chromium"}, time.Hour)

	params := map[string]any{"browser": "chromium", "profile": "Default", "urls": []any{"https://app.example.test/"}}
	cookiesReply, err := d.handleGetCookies(ctx, params)
	if err != nil {
		t.Fatalf("get_cookies: %v", err)
	}
	storageReply, err := d.handleGetWebStorage(ctx, params)
	if err != nil {
		t.Fatalf("get_web_storage: %v", err)
	}
	var wire struct {
		Cookies []cookie.WireCookie `json:"cookies"`
		Origins []cookie.WireOrigin `json:"origins"`
	}
	if err := json.Unmarshal([]byte(marshalResult(t, cookiesReply)), &wire); err != nil {
		t.Fatalf("decode cookies: %v", err)
	}
	if err := json.Unmarshal([]byte(marshalResult(t, storageReply)), &wire); err != nil {
		t.Fatalf("decode origins: %v", err)
	}
	state := cookie.StorageState{}
	for _, w := range wire.Cookies {
		state.Cookies = append(state.Cookies, cookie.FromWire(w))
	}
	for _, w := range wire.Origins {
		state.Origins = append(state.Origins, cookie.OriginFromWire(w))
	}

	for _, tt := range []struct {
		format cookie.OutputFormat
		want   string
	}{
		{
			format: cookie.FormatPlaywright,
			want: `{"cookies": [{"name": "sid", "value": "s3ss10n", "domain": "app.example.test", "path": "/", "expires": -1, "httpOnly": true, "secure": true, "sameSite": "Lax"}], ` +
				`"origins": [{"origin": "https://app.example.test", "localStorage": [{"name": "theme", "value": "dark"}]}]}`,
		},
		{
			format: cookie.FormatWebStorage,
			want:   `{"origins": [{"origin": "https://app.example.test", "localStorage": [{"name": "theme", "value": "dark"}], "sessionStorage": [{"name": "draft", "value": "hi"}]}]}`,
		},
		{
			format: cookie.FormatHeader,
			want:   `sid=s3ss10n`,
		},
	} {
		t.Run(string(tt.format), func(t *testing.T) {
			if got := strings.Join(cookie.Render(state, tt.format), "\n"); got != tt.want {
				t.Fatalf("render %s =\n%s\nwant\n%s", tt.format, got, tt.want)
			}
		})
	}
	if len(consent.promptedReasons) != 0 {
		t.Fatalf("a warm granted key must not prompt; prompted %v", consent.promptedReasons)
	}
}
