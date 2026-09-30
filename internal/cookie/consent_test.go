package cookie

import (
	"strings"
	"testing"
)

var (
	chromeDisplay = Browser{Name: BrowserName("chrome"), Display: "Chrome"}
	arcDisplay    = Browser{Name: BrowserName("arc"), Display: "Arc"}
)

func TestComposeReasonCollapsesWhitespaceAndCaps(t *testing.T) {
	if got := ComposeReason("Chrome", "post   a\n\ttweet"); got != "unlock your Chrome cookies to post a tweet" {
		t.Fatalf("ComposeReason collapse = %q", got)
	}
	// Python's str.split() treats the C0 separators FS/GS/RS/US (U+001C–U+001F) as
	// whitespace; strings.Fields/unicode.IsSpace do not. These must collapse too.
	if got := ComposeReason("Chrome", "post\x1ca\x1dtweet\x1e\x1fnow"); got != "unlock your Chrome cookies to post a tweet now" {
		t.Fatalf("ComposeReason C0-separator collapse = %q", got)
	}
	long := strings.Repeat("x", 300)
	composed := ComposeReason("Chrome", long)
	want := "unlock your Chrome cookies to " + strings.Repeat("x", reasonCap)
	if composed != want {
		t.Fatalf("ComposeReason cap = %q, want %q", composed, want)
	}
	if !strings.HasSuffix(composed, strings.Repeat("x", reasonCap)) {
		t.Fatalf("ComposeReason cap suffix mismatch")
	}
}

func TestComposeReasonMapExamples(t *testing.T) {
	cases := []struct {
		host, reason, want string
	}{
		{"Chrome", "post a tweet", "unlock your Chrome cookies to post a tweet"},
		{"Chrome", "post   a\n\ttweet", "unlock your Chrome cookies to post a tweet"},
		{"Arc", "sync them to yasyf-home:chrome:Default", "unlock your Arc cookies to sync them to yasyf-home:chrome:Default"},
	}
	for _, tc := range cases {
		if got := ComposeReason(tc.host, tc.reason); got != tc.want {
			t.Fatalf("ComposeReason(%q, %q) = %q, want %q", tc.host, tc.reason, got, tc.want)
		}
	}
}

// TestComposeReasonKeepsCompositeRequestorMiddleDot pins that the U+00B7 in a composite
// requestor reference survives the whitespace collapse into the real sheet text.
func TestComposeReasonKeepsCompositeRequestorMiddleDot(t *testing.T) {
	got := ComposeReason("Chrome", "sync them across your Macs for Claude Code · a3283ae1")
	if !strings.Contains(got, "Claude Code · a3283ae1") {
		t.Fatalf("ComposeReason = %q, want it to contain %q verbatim", got, "Claude Code · a3283ae1")
	}
}

func TestComposeBatchReason(t *testing.T) {
	cases := []struct {
		name     string
		browsers []Browser
		reason   string
		want     string
	}{
		{
			name:     "two browsers joined with plus",
			browsers: []Browser{chromeDisplay, arcDisplay},
			reason:   "sync them across your Macs",
			want:     "unlock your Chrome + Arc cookies to sync them across your Macs",
		},
		{
			name:     "whitespace collapses like the single path",
			browsers: []Browser{chromeDisplay, arcDisplay},
			reason:   "post   a\n\ttweet",
			want:     "unlock your Chrome + Arc cookies to post a tweet",
		},
		{
			name:     "cap truncates the reason tail never the browser names",
			browsers: []Browser{chromeDisplay, arcDisplay},
			reason:   strings.Repeat("x", 300),
			want:     "unlock your Chrome + Arc cookies to " + strings.Repeat("x", reasonCap),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ComposeBatchReason(tc.browsers, tc.reason); got != tc.want {
				t.Fatalf("ComposeBatchReason = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestComposeBatchReasonSingleBrowserParity(t *testing.T) {
	for _, reason := range []string{
		"post a tweet",
		"post   a\n\ttweet",
		"sync them to yasyf-home:chrome:Default",
		strings.Repeat("x", 300),
	} {
		batch := ComposeBatchReason([]Browser{chromeDisplay}, reason)
		single := ComposeReason("Chrome", reason)
		if batch != single {
			t.Fatalf("ComposeBatchReason(N=1, %q) = %q, want byte-identical to ComposeReason %q", reason, batch, single)
		}
	}
}
