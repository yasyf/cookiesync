package cookie

import (
	"reflect"
	"testing"
)

func renderedCookieJSON(expires, secure, sameSite string) string {
	return `{"name": "sid", "value": "synthetic-session", "domain": "app.example.test", "path": "/", "expires": ` + expires +
		`, "httpOnly": true, "secure": ` + secure + `, "sameSite": ` + sameSite + `}`
}

func playwrightWith(cookies string) string {
	return `{"cookies": [` + cookies + `], "origins": []}`
}

func TestParseRenderedRoundTripsTheFixtures(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		format  OutputFormat
	}{
		{name: "playwright", fixture: "import_playwright.json", format: FormatPlaywright},
		{name: "webstorage", fixture: "import_webstorage.json", format: FormatWebStorage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := readGolden(t, tt.fixture)
			state, err := ParseRendered([]byte(data), tt.format)
			if err != nil {
				t.Fatalf("ParseRendered: %v", err)
			}
			lines := Render(state, tt.format)
			if len(lines) != 1 {
				t.Fatalf("Render emitted %d lines, want 1", len(lines))
			}
			if got := lines[0] + "\n"; got != data {
				t.Fatalf("re-render = %q, want %q", got, data)
			}
		})
	}
}

func TestParseRenderedMapsEveryField(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		format  OutputFormat
		want    StorageState
	}{
		{
			name:    "playwright",
			fixture: "import_playwright.json",
			format:  FormatPlaywright,
			want: StorageState{
				Cookies: []Cookie{
					{
						HostKey:    "api.third.test",
						Name:       "csrf",
						Value:      "töken",
						Path:       "/v1",
						ExpiresUTC: 15746918400000000,
						SameSite:   2,
					},
					{
						HostKey:    ".other.test",
						Name:       "pref",
						Value:      "dark",
						Path:       "/",
						ExpiresUTC: 15746918400015625,
						IsSecure:   true,
						SameSite:   0,
					},
					{
						HostKey:    "app.example.test",
						Name:       "sid",
						Value:      "synthetic-session",
						Path:       "/",
						ExpiresUTC: 0,
						IsSecure:   true,
						IsHTTPOnly: true,
						SameSite:   1,
					},
				},
				Origins: []OriginStorage{{
					Origin:       "https://app.example.test",
					LocalStorage: []WebStorageEntry{{Name: "theme", Value: "dark"}},
				}},
			},
		},
		{
			name:    "webstorage",
			fixture: "import_webstorage.json",
			format:  FormatWebStorage,
			want: StorageState{
				Origins: []OriginStorage{
					{
						Origin:         "https://app.example.test",
						LocalStorage:   []WebStorageEntry{{Name: "theme", Value: "dark"}},
						SessionStorage: []WebStorageEntry{{Name: "draft", Value: "synthetic"}},
					},
					{
						Origin:         "https://app.example.test:8443",
						LocalStorage:   []WebStorageEntry{},
						SessionStorage: []WebStorageEntry{{Name: "tab", Value: "1"}},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRendered([]byte(readGolden(t, tt.fixture)), tt.format)
			if err != nil {
				t.Fatalf("ParseRendered: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseRendered = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseRenderedExpiryAtTheChromeCeiling(t *testing.T) {
	tests := []struct {
		name    string
		expires string
		want    ChromeMicros
	}{
		{name: "the rendered ceiling parses back", expires: "9211727563254.0", want: 9223372036854000000},
		{name: "half a second past the rendered ceiling still fits", expires: "9211727563254.5", want: 9223372036854500000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRendered([]byte(playwrightWith(renderedCookieJSON(tt.expires, "true", `"Lax"`))), FormatPlaywright)
			if err != nil {
				t.Fatalf("ParseRendered: %v", err)
			}
			if len(got.Cookies) != 1 || got.Cookies[0].ExpiresUTC != tt.want {
				t.Fatalf("ParseRendered cookies = %+v, want one cookie expiring at %d", got.Cookies, tt.want)
			}
		})
	}
}

func TestParseRenderedRefuses(t *testing.T) {
	tests := []struct {
		name   string
		doc    string
		format OutputFormat
		want   string
	}{
		{
			name:   "unknown top-level key",
			doc:    `{"cookies": [], "origins": [], "extra": 1}`,
			format: FormatPlaywright,
			want:   `parse playwright document: json: unknown field "extra"`,
		},
		{
			name:   "trailing document",
			doc:    `{"cookies": [], "origins": []} {}`,
			format: FormatPlaywright,
			want:   `parse playwright document: cookie wire carries trailing JSON`,
		},
		{
			name:   "webstorage document read as playwright",
			doc:    `{"origins": []}`,
			format: FormatPlaywright,
			want:   `parse playwright document: missing "cookies"`,
		},
		{
			name:   "null cookies",
			doc:    `{"cookies": null, "origins": []}`,
			format: FormatPlaywright,
			want:   `parse playwright document: missing "cookies"`,
		},
		{
			name:   "playwright document without origins",
			doc:    `{"cookies": []}`,
			format: FormatPlaywright,
			want:   `parse playwright document: missing "origins"`,
		},
		{
			name:   "playwright document read as webstorage",
			doc:    readGolden(t, "import_playwright.json"),
			format: FormatWebStorage,
			want:   `parse webstorage document: json: unknown field "cookies"`,
		},
		{
			name:   "webstorage document without origins",
			doc:    `{}`,
			format: FormatWebStorage,
			want:   `parse webstorage document: missing "origins"`,
		},
		{
			name:   "sessionStorage in a playwright origin",
			doc:    `{"cookies": [], "origins": [{"origin": "https://app.example.test", "localStorage": [{"name": "theme", "value": "dark"}], "sessionStorage": []}]}`,
			format: FormatPlaywright,
			want:   `parse playwright document: json: unknown field "sessionStorage"`,
		},
		{
			name:   "lowercase sameSite",
			doc:    playwrightWith(renderedCookieJSON("-1", "true", `"none"`)),
			format: FormatPlaywright,
			want:   `parse playwright document: cookies[0] sameSite is not None, Lax, or Strict`,
		},
		{
			name:   "sameSite None without secure",
			doc:    playwrightWith(renderedCookieJSON("-1", "false", `"None"`)),
			format: FormatPlaywright,
			want:   `parse playwright document: cookies[0] is sameSite None without secure`,
		},
		{
			name:   "zero expiry",
			doc:    playwrightWith(renderedCookieJSON("0", "true", `"Lax"`)),
			format: FormatPlaywright,
			want:   `parse playwright document: cookies[0] expires is neither -1 nor a positive Unix time`,
		},
		{
			name:   "negative expiry other than -1",
			doc:    playwrightWith(renderedCookieJSON("-2", "true", `"Lax"`)),
			format: FormatPlaywright,
			want:   `parse playwright document: cookies[0] expires is neither -1 nor a positive Unix time`,
		},
		{
			name:   "quoted -1 expiry",
			doc:    playwrightWith(renderedCookieJSON(`"-1"`, "true", `"Lax"`)),
			format: FormatPlaywright,
			want:   `parse playwright document: cookies[0] expires is neither -1 nor a positive Unix time`,
		},
		{
			name:   "null expiry",
			doc:    playwrightWith(renderedCookieJSON("null", "true", `"Lax"`)),
			format: FormatPlaywright,
			want:   `parse playwright document: cookies[0] expires is neither -1 nor a positive Unix time`,
		},
		{
			name:   "-1.0 session expiry on the second cookie",
			doc:    playwrightWith(renderedCookieJSON("-1", "true", `"Lax"`) + ", " + renderedCookieJSON("-1.0", "true", `"Lax"`)),
			format: FormatPlaywright,
			want:   `parse playwright document: cookies[1] expires is neither -1 nor a positive Unix time`,
		},
		{
			name:   "expiry past the Chrome timestamp range",
			doc:    playwrightWith(renderedCookieJSON("1e13", "true", `"Lax"`)),
			format: FormatPlaywright,
			want:   `parse playwright document: cookies[0] expires is neither -1 nor a positive Unix time`,
		},
		{
			name:   "expiry just past the Chrome ceiling",
			doc:    playwrightWith(renderedCookieJSON("9211727563254.78", "true", `"Lax"`)),
			format: FormatPlaywright,
			want:   `parse playwright document: cookies[0] expires is neither -1 nor a positive Unix time`,
		},
		{
			name:   "expiry carrying an object never echoes it",
			doc:    playwrightWith(renderedCookieJSON(`{"value": "SECRET"}`, "true", `"Lax"`)),
			format: FormatPlaywright,
			want:   `parse playwright document: cookies[0] expires is neither -1 nor a positive Unix time`,
		},
		{
			name:   "invalid escape in a value never echoes the byte",
			doc:    `{"cookies": [{"name": "sid", "value": "\q"}], "origins": []}`,
			format: FormatPlaywright,
			want:   `parse playwright document: invalid JSON at offset 41`,
		},
		{
			name:   "cookies carrying a string never echoes it",
			doc:    `{"cookies": "SECRET", "origins": []}`,
			format: FormatPlaywright,
			want:   `parse playwright document: wrong JSON type at offset 20`,
		},
		{
			name:   "origins carrying a string never echoes it",
			doc:    `{"origins": "SECRET"}`,
			format: FormatWebStorage,
			want:   `parse webstorage document: wrong JSON type at offset 20`,
		},
		{
			name:   "cookie path not rooted at /",
			doc:    playwrightWith(`{"name": "sid", "value": "synthetic-session", "domain": "app.example.test", "path": "@evil.com/", "expires": -1, "httpOnly": true, "secure": true, "sameSite": "Lax"}`),
			format: FormatPlaywright,
			want:   `parse playwright document: cookies[0] path must start with /`,
		},
		{
			name:   "cookie without path",
			doc:    playwrightWith(`{"name": "sid", "value": "synthetic-session", "domain": "app.example.test", "expires": -1, "httpOnly": true, "secure": true, "sameSite": "Lax"}`),
			format: FormatPlaywright,
			want:   `parse playwright document: cookies[0] missing "path"`,
		},
		{
			name:   "playwright origin with empty localStorage",
			doc:    `{"cookies": [], "origins": [{"origin": "https://app.example.test", "localStorage": []}]}`,
			format: FormatPlaywright,
			want:   `parse playwright document: origins[0] carries no localStorage`,
		},
		{
			name:   "playwright localStorage entry without value",
			doc:    `{"cookies": [], "origins": [{"origin": "https://app.example.test", "localStorage": [{"name": "theme"}]}]}`,
			format: FormatPlaywright,
			want:   `parse playwright document: origins[0].localStorage[0] missing "value"`,
		},
		{
			name:   "webstorage origin without sessionStorage",
			doc:    `{"origins": [{"origin": "https://app.example.test", "localStorage": []}]}`,
			format: FormatWebStorage,
			want:   `parse webstorage document: origins[0] missing "sessionStorage"`,
		},
		{
			name:   "webstorage sessionStorage entry without name",
			doc:    `{"origins": [{"origin": "https://app.example.test", "localStorage": [], "sessionStorage": []}, {"origin": "https://app.example.test:8443", "localStorage": [], "sessionStorage": [{"value": "1"}]}]}`,
			format: FormatWebStorage,
			want:   `parse webstorage document: origins[1].sessionStorage[0] missing "name"`,
		},
		{
			name:   "header format",
			doc:    `sid=synthetic-session`,
			format: FormatHeader,
			want:   `cannot parse a header document`,
		},
		{
			name:   "json format",
			doc:    `[]`,
			format: FormatJSON,
			want:   `cannot parse a json document`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRendered([]byte(tt.doc), tt.format)
			if err == nil {
				t.Fatalf("ParseRendered = %+v, want error %q", got, tt.want)
			}
			if err.Error() != tt.want {
				t.Fatalf("ParseRendered error = %q, want %q", err.Error(), tt.want)
			}
			if !reflect.DeepEqual(got, StorageState{}) {
				t.Fatalf("ParseRendered state = %+v, want the zero StorageState", got)
			}
		})
	}
}
