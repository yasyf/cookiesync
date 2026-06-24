package cookie

import (
	"sort"
	"testing"
)

// mergeCookie mirrors the Python test_merge `_cookie` factory: a fully populated
// cookie with overridable identity fields, so a test can vary exactly one dimension
// of the merge key or rank.
func mergeCookie(opts ...func(*Cookie)) Cookie {
	c := Cookie{
		HostKey:              ".x.com",
		Name:                 "sid",
		Value:                "v",
		Path:                 "/",
		ExpiresUTC:           13_400_000_000_000_000,
		LastUpdateUTC:        13_350_000_000_000_000,
		CreationUTC:          13_300_000_000_000_000,
		IsSecure:             true,
		IsHTTPOnly:           true,
		SameSite:             2,
		SourceScheme:         2,
		SourcePort:           443,
		TopFrameSiteKey:      "",
		HasCrossSiteAncestor: 0,
	}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

func host(h HostKey) func(*Cookie) { return func(c *Cookie) { c.HostKey = h } }
func name(n string) func(*Cookie)  { return func(c *Cookie) { c.Name = n } }
func value(v string) func(*Cookie) { return func(c *Cookie) { c.Value = v } }
func path(p string) func(*Cookie)  { return func(c *Cookie) { c.Path = p } }

func lastUpdate(u ChromeMicros) func(*Cookie) {
	return func(c *Cookie) { c.LastUpdateUTC = u }
}
func sourcePort(p int) func(*Cookie) { return func(c *Cookie) { c.SourcePort = p } }
func topFrame(s string) func(*Cookie) {
	return func(c *Cookie) { c.TopFrameSiteKey = s }
}

func hostKeys(cookies []Cookie) map[HostKey]bool {
	out := map[HostKey]bool{}
	for _, c := range cookies {
		out[c.HostKey] = true
	}
	return out
}

func ports(cookies []Cookie) map[int]bool {
	out := map[int]bool{}
	for _, c := range cookies {
		out[c.SourcePort] = true
	}
	return out
}

func frames(cookies []Cookie) map[string]bool {
	out := map[string]bool{}
	for _, c := range cookies {
		out[c.TopFrameSiteKey] = true
	}
	return out
}

func TestMergeEmptySourcesYieldEmpty(t *testing.T) {
	if got := Merge(); len(got) != 0 {
		t.Fatalf("Merge() = %v, want empty", got)
	}
	if got := Merge(nil, nil, nil); len(got) != 0 {
		t.Fatalf("Merge(nil, nil, nil) = %v, want empty", got)
	}
}

func TestMergeNewestLastUpdateWins(t *testing.T) {
	old := mergeCookie(value("old"), lastUpdate(13_300_000_000_000_000))
	fresh := mergeCookie(value("new"), lastUpdate(13_399_000_000_000_000))
	if got := Merge([]Cookie{old}, []Cookie{fresh}); len(got) != 1 || got[0] != fresh {
		t.Fatalf("Merge([old],[new]) = %v, want [new]", got)
	}
	if got := Merge([]Cookie{fresh}, []Cookie{old}); len(got) != 1 || got[0] != fresh {
		t.Fatalf("Merge([new],[old]) = %v, want [new] (order must not matter)", got)
	}
}

func TestMergeDisjointUnionKeepsEveryCookie(t *testing.T) {
	a := mergeCookie(host(".a.com"), name("a"))
	b := mergeCookie(host(".b.com"), name("b"))
	c := mergeCookie(host(".c.com"), name("c"))
	merged := Merge([]Cookie{a}, []Cookie{b, c})
	if len(merged) != 3 {
		t.Fatalf("len = %d, want 3", len(merged))
	}
	want := map[HostKey]bool{".a.com": true, ".b.com": true, ".c.com": true}
	if got := hostKeys(merged); len(got) != 3 || !mapsEqual(got, want) {
		t.Fatalf("host keys = %v, want %v", got, want)
	}
}

func TestMergeSameLogicalKeyAcrossThreeSourcesCollapsesToOne(t *testing.T) {
	s1 := mergeCookie(value("1"), lastUpdate(13_310_000_000_000_000))
	s2 := mergeCookie(value("2"), lastUpdate(13_320_000_000_000_000))
	s3 := mergeCookie(value("3"), lastUpdate(13_330_000_000_000_000))
	merged := Merge([]Cookie{s1}, []Cookie{s2}, []Cookie{s3})
	if len(merged) != 1 {
		t.Fatalf("len = %d, want 1", len(merged))
	}
	if merged[0].Value != "3" {
		t.Fatalf("value = %q, want %q (newest last_update across all sources)", merged[0].Value, "3")
	}
}

func TestMergeFullUniquenessTupleDistinguishesSourcePort(t *testing.T) {
	a := mergeCookie(name("sid"), path("/"), sourcePort(443))
	b := mergeCookie(name("sid"), path("/"), sourcePort(8443))
	merged := Merge([]Cookie{a}, []Cookie{b})
	if len(merged) != 2 {
		t.Fatalf("len = %d, want 2 (same name+path, different source_port are DISTINCT)", len(merged))
	}
	if got := ports(merged); !mapsEqual(got, map[int]bool{443: true, 8443: true}) {
		t.Fatalf("ports = %v, want {443, 8443}", got)
	}
}

func TestMergeFullUniquenessTupleDistinguishesTopFrameSiteKey(t *testing.T) {
	a := mergeCookie(name("sid"), path("/"), topFrame(""))
	b := mergeCookie(name("sid"), path("/"), topFrame("https://embed.example"))
	merged := Merge([]Cookie{a}, []Cookie{b})
	if len(merged) != 2 {
		t.Fatalf("len = %d, want 2 (different top_frame_site_key are DISTINCT)", len(merged))
	}
	if got := frames(merged); !mapsEqual(got, map[string]bool{"": true, "https://embed.example": true}) {
		t.Fatalf("frames = %v", got)
	}
}

func TestMergeDeterministicTieBreakOnEqualLastUpdate(t *testing.T) {
	left := mergeCookie(value("alpha"), lastUpdate(13_350_000_000_000_000))
	right := mergeCookie(value("omega"), lastUpdate(13_350_000_000_000_000))
	if keyOf(left) != keyOf(right) {
		t.Fatalf("expected identical merge keys for the tie-break case")
	}
	forward := Merge([]Cookie{left}, []Cookie{right})
	reverse := Merge([]Cookie{right}, []Cookie{left})
	if len(forward) != 1 || len(reverse) != 1 {
		t.Fatalf("forward=%d reverse=%d, want 1 each", len(forward), len(reverse))
	}
	if forward[0].Value != reverse[0].Value {
		t.Fatalf("tie-break depended on source order: forward=%q reverse=%q", forward[0].Value, reverse[0].Value)
	}
}

// TestContentHashMatchesPythonBytes pins ContentHash to the exact hex digests the
// recovered Python merge.content_hash emits for the same inputs.
func TestContentHashMatchesPythonBytes(t *testing.T) {
	cases := []struct {
		name string
		c    Cookie
		want string
	}{
		{
			"alpha",
			mergeCookie(value("alpha")),
			"357eed6ecdf9b8f4439a13ca7253bdf64058f890e21ca2b24d1d685466f15b8e",
		},
		{
			"omega",
			mergeCookie(value("omega")),
			"c2e253ab8a71f82e5948ac87e0c914c2c910701735f6888f81f3154eea52752f",
		},
		{
			"unicode",
			Cookie{
				Value:      "qu\"ote é😀\t\x01end",
				ExpiresUTC: 13_544_473_600_000_000,
				SameSite:   1,
				IsSecure:   false,
				IsHTTPOnly: true,
			},
			"f8e88a747a2197a1a21b9ce94f669a5cf53879e5ba4782df89ff7a7b0eb3841d",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ContentHash(tc.c); got != tc.want {
				t.Fatalf("ContentHash = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestMergeOrderIndependentForLargeShuffle asserts Merge converges to the same set
// regardless of how the same cookies are partitioned and ordered across sources.
func TestMergeOrderIndependentForLargeShuffle(t *testing.T) {
	cookies := []Cookie{
		mergeCookie(host(".a.com"), name("s"), value("a1"), lastUpdate(13_310_000_000_000_000)),
		mergeCookie(host(".a.com"), name("s"), value("a2"), lastUpdate(13_320_000_000_000_000)),
		mergeCookie(host(".b.com"), name("t"), value("b1"), lastUpdate(13_330_000_000_000_000)),
		mergeCookie(host(".b.com"), name("t"), value("b2"), lastUpdate(13_330_000_000_000_000)),
		mergeCookie(host(".c.com"), name("u"), value("c1")),
	}
	forward := canonical(Merge([]Cookie{cookies[0], cookies[2]}, []Cookie{cookies[1], cookies[3], cookies[4]}))
	reverse := canonical(Merge([]Cookie{cookies[4], cookies[3]}, []Cookie{cookies[1]}, []Cookie{cookies[2], cookies[0]}))
	if len(forward) != 3 {
		t.Fatalf("len = %d, want 3", len(forward))
	}
	for i := range forward {
		if forward[i] != reverse[i] {
			t.Fatalf("merge not order-independent at %d: %+v vs %+v", i, forward[i], reverse[i])
		}
	}
}

func canonical(cookies []Cookie) []Cookie {
	sort.Slice(cookies, func(i, j int) bool {
		if cookies[i].HostKey != cookies[j].HostKey {
			return cookies[i].HostKey < cookies[j].HostKey
		}
		return cookies[i].Name < cookies[j].Name
	})
	return cookies
}

func mapsEqual[K comparable](a, b map[K]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
