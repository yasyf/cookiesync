package cookie

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Golden bytes captured from the recovered Python serialize.py (json.dumps with
// ensure_ascii=True). Render must reproduce these byte-for-byte. The Unicode-stress
// goldens live in testdata/ (written by Python) so their exact \uXXXX vs raw-UTF-8
// bytes are unambiguous.
const (
	goldenPlaywright = `{"cookies": [{"name": "sid", "value": "abc", "domain": ".example.com", "path": "/", "expires": 2000000000.0, "httpOnly": true, "secure": true, "sameSite": "Strict"}, {"name": "tok", "value": "xyz", "domain": "host.example.com", "path": "/app", "expires": -1, "httpOnly": false, "secure": true, "sameSite": "None"}], "origins": []}`
	goldenJSON       = `[{"name": "sid", "value": "abc", "domain": ".example.com", "path": "/", "expires": 2000000000.0, "httpOnly": true, "secure": true, "sameSite": "Strict"}, {"name": "tok", "value": "xyz", "domain": "host.example.com", "path": "/app", "expires": -1, "httpOnly": false, "secure": true, "sameSite": "None"}]`
)

func sid() Cookie {
	return Cookie{
		HostKey:    ".example.com",
		Name:       "sid",
		Value:      "abc",
		Path:       "/",
		ExpiresUTC: unixSecondsToChromeMicros(2_000_000_000.0),
		IsSecure:   true,
		IsHTTPOnly: true,
		SameSite:   2,
	}
}

func tok() Cookie {
	return Cookie{
		HostKey:    "host.example.com",
		Name:       "tok",
		Value:      "xyz",
		Path:       "/app",
		ExpiresUTC: 0,
		IsSecure:   false,
		IsHTTPOnly: false,
		SameSite:   0,
	}
}

func state() StorageState { return StorageState{Cookies: []Cookie{sid(), tok()}} }

// fayeStorage is one origin carrying a localStorage auth blob and a sessionStorage value
// with an embedded quote, so the JSON escaping is exercised in the goldens.
func fayeStorage() []OriginStorage {
	return []OriginStorage{{
		Origin:         "https://app.findfaye.com",
		LocalStorage:   []WebStorageEntry{{Name: "auth", Value: `{"t":1}`}},
		SessionStorage: []WebStorageEntry{{Name: "sid", Value: `s"v`}},
	}}
}

func readGolden(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // test reads its own testdata fixture by name.
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return string(data)
}

func TestRenderEmitsExactLines(t *testing.T) {
	cases := []struct {
		name   string
		format OutputFormat
		want   []string
	}{
		{"playwright", FormatPlaywright, []string{goldenPlaywright}},
		{"json", FormatJSON, []string{goldenJSON}},
		{
			"netscape",
			FormatNetscape,
			[]string{
				"# Netscape HTTP Cookie File",
				".example.com\tTRUE\t/\tTRUE\t2000000000\tsid\tabc",
				"host.example.com\tFALSE\t/app\tFALSE\t0\ttok\txyz",
			},
		},
		{"header", FormatHeader, []string{"sid=abc; tok=xyz"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Render(state(), tc.format); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Render(%s):\n got = %#v\nwant = %#v", tc.format, got, tc.want)
			}
		})
	}
}

// TestRenderPlaywrightEmitsPopulatedOrigins pins the storageState with real origins: the
// cookie bytes are unchanged from the empty-origins golden and the "origins" array now
// carries each origin's localStorage (Playwright storageState has no sessionStorage slot).
func TestRenderPlaywrightEmitsPopulatedOrigins(t *testing.T) {
	cookiesPart := strings.TrimSuffix(goldenPlaywright, `, "origins": []}`)
	want := cookiesPart + `, "origins": [{"origin": "https://app.findfaye.com", "localStorage": [{"name": "auth", "value": "{\"t\":1}"}]}]}`
	got := Render(StorageState{Cookies: []Cookie{sid(), tok()}, Origins: fayeStorage()}, FormatPlaywright)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("playwright with origins:\n got = %q\nwant = %q", got[0], want)
	}
}

// TestRenderWebStorageSidecar pins the webstorage sidecar: {"origins": [...]} carrying
// both localStorage and sessionStorage, the only channel that emits sessionStorage.
func TestRenderWebStorageSidecar(t *testing.T) {
	want := `{"origins": [{"origin": "https://app.findfaye.com", "localStorage": [{"name": "auth", "value": "{\"t\":1}"}], "sessionStorage": [{"name": "sid", "value": "s\"v"}]}]}`
	got := Render(StorageState{Origins: fayeStorage()}, FormatWebStorage)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("webstorage sidecar:\n got = %q\nwant = %q", got[0], want)
	}
}

// TestRenderPlaywrightDropsSessionOnlyOrigin proves an origin with no localStorage does
// not appear in the Playwright origins array, which has no sessionStorage to carry.
func TestRenderPlaywrightDropsSessionOnlyOrigin(t *testing.T) {
	sessionOnly := []OriginStorage{{Origin: "https://app.findfaye.com", SessionStorage: []WebStorageEntry{{Name: "sid", Value: "v"}}}}
	got := Render(StorageState{Origins: sessionOnly}, FormatPlaywright)
	if len(got) != 1 || got[0] != `{"cookies": [], "origins": []}` {
		t.Fatalf("session-only origin in playwright = %q, want empty origins", got[0])
	}
}

func TestRenderEmptyStatePerFormat(t *testing.T) {
	empty := StorageState{}
	cases := []struct {
		name   string
		format OutputFormat
		want   []string
	}{
		{"playwright", FormatPlaywright, []string{`{"cookies": [], "origins": []}`}},
		{"json", FormatJSON, []string{"[]"}},
		{"netscape", FormatNetscape, []string{"# Netscape HTTP Cookie File"}},
		{"header", FormatHeader, []string{""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Render(empty, tc.format); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Render(empty, %s) = %#v, want %#v", tc.format, got, tc.want)
			}
		})
	}
}

func TestNetscapeDotFlagTracksLeadingDot(t *testing.T) {
	rows := Render(state(), FormatNetscape)[1:]
	if field := strings.Split(rows[0], "\t")[1]; field != "TRUE" {
		t.Fatalf(".example.com includeSubdomains = %q, want TRUE", field)
	}
	if field := strings.Split(rows[1], "\t")[1]; field != "FALSE" {
		t.Fatalf("host-only includeSubdomains = %q, want FALSE", field)
	}
}

func TestNetscapeSessionCookieExpiryIsZero(t *testing.T) {
	if field := strings.Split(Render(state(), FormatNetscape)[2], "\t")[4]; field != "0" {
		t.Fatalf("session expiry = %q, want 0", field)
	}
}

func TestSameSiteNoneForcesSecureTrue(t *testing.T) {
	// tok has IsSecure=false and SameSite=0 (None); rendering must force secure.
	pw := playwrightCookie(tok())
	if !strings.Contains(pw, `"sameSite": "None"`) {
		t.Fatalf("expected sameSite None in %s", pw)
	}
	if !strings.Contains(pw, `"secure": true`) {
		t.Fatalf("sameSite=None must force secure=true, got %s", pw)
	}
}

func TestSessionCookieExpiryRendersMinusOne(t *testing.T) {
	if got := expiresJSON(tok().ExpiresUTC); got != "-1" {
		t.Fatalf("session expires = %q, want -1 (integer)", got)
	}
}

// TestRenderUnicodeMatchesPythonBytes pins the JSON and netscape rendering of a
// cookie with non-ASCII, an astral emoji, a quote, a tab, and a control char to the
// exact bytes Python emits, loaded from testdata: \uXXXX surrogate pairs in the JSON
// form, raw UTF-8 in the netscape form. The input's non-ASCII bytes are written with
// explicit Go escapes (é = é, \U0001F600 = 😀, â = â) so the fixture is unambiguous.
func TestRenderUnicodeMatchesPythonBytes(t *testing.T) {
	uni := Cookie{
		HostKey:    ".café.example.com",
		Name:       "na/me",
		Value:      "qu\"ote é\U0001F600\t\x01end",
		Path:       "/pâth",
		ExpiresUTC: unixSecondsToChromeMicros(1_900_000_000.5),
		IsSecure:   true,
		IsHTTPOnly: false,
		SameSite:   1,
	}
	if got := Render(StorageState{Cookies: []Cookie{uni}}, FormatJSON); len(got) != 1 || got[0] != readGolden(t, "unicode_cookie.json") {
		t.Fatalf("unicode JSON:\n got  = %q\nwant = %q", got[0], readGolden(t, "unicode_cookie.json"))
	}
	if got := netscapeLine(uni); got != readGolden(t, "unicode_cookie.netscape") {
		t.Fatalf("unicode netscape:\n got  = %q\nwant = %q", got, readGolden(t, "unicode_cookie.netscape"))
	}
}

func TestExpiresJSONFloatForms(t *testing.T) {
	cases := []struct {
		name    string
		seconds float64
		want    string
	}{
		{"whole", 2_000_000_000.0, "2000000000.0"},
		{"fractional", 1_900_000_000.5, "1900000000.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := expiresJSON(unixSecondsToChromeMicros(tc.seconds)); got != tc.want {
				t.Fatalf("expiresJSON(%v) = %q, want %q", tc.seconds, got, tc.want)
			}
		})
	}
}

func TestNormalizeGetcookieRecordMapsFields(t *testing.T) {
	cookie := NormalizeGetcookieRecord(
		map[string]any{
			"name":   "session",
			"value":  "deadbeef",
			"domain": ".github.com",
			"path":   "/login",
			"expiry": float64(1_900_000_000),
			"meta": map[string]any{
				"secure":   true,
				"httpOnly": true,
				"sameSite": "Strict",
			},
		},
		"https://github.com",
	)
	if cookie.HostKey != ".github.com" {
		t.Fatalf("host_key = %q", cookie.HostKey)
	}
	if cookie.Name != "session" || cookie.Value != "deadbeef" || cookie.Path != "/login" {
		t.Fatalf("name/value/path = %q/%q/%q", cookie.Name, cookie.Value, cookie.Path)
	}
	if !cookie.IsSecure || !cookie.IsHTTPOnly {
		t.Fatalf("secure=%v httponly=%v, want both true", cookie.IsSecure, cookie.IsHTTPOnly)
	}
	if cookie.SameSite != 2 {
		t.Fatalf("samesite = %d, want 2 (Strict)", cookie.SameSite)
	}
	if want := unixSecondsToChromeMicros(1_900_000_000.0); cookie.ExpiresUTC != want {
		t.Fatalf("expires_utc = %d, want %d", cookie.ExpiresUTC, want)
	}
}

func TestNormalizeGetcookieRecordDefaultsSessionCookieToMinusOne(t *testing.T) {
	cookie := NormalizeGetcookieRecord(map[string]any{"name": "n", "value": "v"}, "https://x.com")
	pw := playwrightCookie(cookie)
	for _, want := range []string{`"domain": "x.com"`, `"path": "/"`, `"expires": -1`, `"secure": true`, `"sameSite": "Lax"`} {
		if !strings.Contains(pw, want) {
			t.Fatalf("expected %s in %s", want, pw)
		}
	}
}
