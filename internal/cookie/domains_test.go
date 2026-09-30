package cookie

import "testing"

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want Host
	}{
		{"bare", "x.com", "x.com"},
		{"strip-scheme", "https://x.com", "x.com"},
		{"strip-path-query", "https://x.com/path/to?q=1", "x.com"},
		{"strip-port", "https://x.com:8443", "x.com"},
		{"strip-userinfo", "https://user:pw@x.com/p", "x.com"},
		{"strip-leading-dot", ".x.com", "x.com"},
		{"trim-and-lowercase", "  HTTPS://X.COM/  ", "x.com"},
		{"subdomain-kept", "sub.x.com", "sub.x.com"},
		{"fragment-cut-before-userinfo", "https://evil.test#@app.example.test", "evil.test"},
		{"fragment-scheme-is-not-a-scheme", "evil.test#@https://app.example.test", "evil.test"},
		{"backslash-cut-before-userinfo", `https://evil.com\@example.test`, "evil.com"},
		{"userinfo-with-path", "https://user:pw@app.example.test/x", "app.example.test"},
		{"ipv6-keeps-brackets-drops-port", "https://[2001:db8::1]:8443/p", "[2001:db8::1]"},
		{"ipv6-lowercased", "[2001:DB8::2]", "[2001:db8::2]"},
		{"bare-host-port", "app.example.test:443", "app.example.test"},
		{"query-and-fragment", "https://app.example.test?x=1#f", "app.example.test"},
		{"backslash-scheme-is-not-a-scheme", `evil.test\https://app.example.test`, "evil.test"},
		{"path-scheme-is-not-a-scheme", "example.test/x://app.example.test", "example.test"},
		{"non-ascii-is-never-folded", "İ.example.test", "İ.example.test"},
		{"ascii-beside-non-ascii-is-lowered", "İ.Example.TEST", "İ.example.test"},
		{"dot-is-empty", ".", ""},
		{"dots-are-empty", "..", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeHost(tc.raw); got != tc.want {
				t.Fatalf("NormalizeHost(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestURLScheme(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"https", "https://x.com", "https"},
		{"http", "http://x.com", "http"},
		{"lowercased", "HTTP://X.COM", "http"},
		{"bare-defaults-https", "x.com", "https"},
		{"backslash-scheme-defaults-https", `evil.test\https://x.com`, "https"},
		{"path-scheme-defaults-https", "x.com/a://b", "https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := URLScheme(tc.raw); got != tc.want {
				t.Fatalf("URLScheme(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestApplies(t *testing.T) {
	cases := []struct {
		name    string
		hostKey HostKey
		host    Host
		applies bool
	}{
		{"dot-domain-matches-base", ".x.com", "x.com", true},
		{"dot-domain-matches-subdomain", ".x.com", "sub.x.com", true},
		{"dot-domain-matches-deep-subdomain", ".x.com", "deep.sub.x.com", true},
		{"dot-domain-rejects-suffix-imposter", ".x.com", "notx.com", false},
		{"dot-domain-rejects-other", ".x.com", "y.com", false},
		{"host-only-exact", "x.com", "x.com", true},
		{"host-only-rejects-subdomain", "x.com", "sub.x.com", false},
		{"host-only-rejects-other", "x.com", "y.com", false},
		{"case-insensitive", ".X.COM", "sub.x.com", true},
		{"non-ascii-host-never-folds-to-host-only", "i.example.test", "İ.example.test", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Applies(tc.hostKey, tc.host); got != tc.applies {
				t.Fatalf("Applies(%q, %q) = %v, want %v", tc.hostKey, tc.host, got, tc.applies)
			}
		})
	}
}
