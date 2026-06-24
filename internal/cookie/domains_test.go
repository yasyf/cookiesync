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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Applies(tc.hostKey, tc.host); got != tc.applies {
				t.Fatalf("Applies(%q, %q) = %v, want %v", tc.hostKey, tc.host, got, tc.applies)
			}
		})
	}
}
