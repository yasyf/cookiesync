package cookie

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/yasyf/cookiesync/internal/helper"
	"github.com/yasyf/cookiesync/internal/paths"
)

// Parity oracles ported from the original Python tests/cookie/test_consent.py. The
// FakeRunner there monkeypatched anyio.run_process; here a temp shell script stands
// in for the signed helper so the real subprocess boundary (argv, env, exit codes,
// binary stdin/stdout) is exercised.

const (
	testPassword    = "peanuts-safe-storage-key"
	testArcPassword = "arc-safe-storage-secret"
)

// staleBatchStderr duplicates helper.unknownSubcommandStderr as a tripwire: a fake
// helper emitting exactly this line with exit 2 must route ObtainKeys onto the
// per-browser vault-retrieve fallback. If the deployed helper's diagnostic ever
// changes, this test and the sniffing constant must change together.
const staleBatchStderr = "keyhelper: unknown subcommand 'vault-batch-retrieve'\n"

func chrome(t *testing.T) Browser {
	t.Helper()
	b, err := Lookup(BrowserName("chrome"))
	if err != nil {
		t.Fatalf("lookup chrome: %v", err)
	}
	return b
}

func arc(t *testing.T) Browser {
	t.Helper()
	b, err := Lookup(BrowserName("arc"))
	if err != nil {
		t.Fatalf("lookup arc: %v", err)
	}
	return b
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// fakeHelperSpec scripts a fake helper's per-verb exit code, stdout, and stderr.
// retrieveCode2, when set, is returned on the second and later vault-retrieve
// calls (the ACL re-enroll retry, or the second browser of a stale-helper loop).
type fakeHelperSpec struct {
	batchCode     int
	batchOut      string
	batchStderr   string
	retrieveCode  int
	retrieveOut   string
	retrieveCode2 int
	retrieveOut2  string
	enrollCode    int
}

// writeFakeHelper writes an executable shell script that emulates the helper's
// vault-* subcommands per spec, appending one line per invocation
// ("<verb> reason=<COOKIESYNC_TOUCHID_REASON>") to a log file and dumping a
// vault-batch-retrieve's item args, one per line, to an args file. Any other verb
// (vault-status above all) exits 99, so a resurrected blank-sheet probe fails the
// test loudly. It returns the script, log, and args paths.
func writeFakeHelper(t *testing.T, spec fakeHelperSpec) (script, logPath, argsPath string) {
	t.Helper()
	dir := t.TempDir()
	script = filepath.Join(dir, "cookiesync-keyhelper")
	logPath = filepath.Join(dir, "calls.log")
	argsPath = filepath.Join(dir, "batch.args")
	body := `#!/bin/sh
verb="$1"
printf '%s reason=%s\n' "$verb" "$COOKIESYNC_TOUCHID_REASON" >> "` + logPath + `"
case "$verb" in
vault-batch-retrieve)
  shift
  printf '%s\n' "$@" > "` + argsPath + `"
  printf '%s' "` + spec.batchOut + `"
  printf '%s' "` + spec.batchStderr + `" >&2
  exit ` + strconv.Itoa(spec.batchCode) + `
  ;;
vault-retrieve)
  n=$(grep -c '^vault-retrieve ' "` + logPath + `")
  if [ "$n" -ge 2 ]; then
    printf '%s' "` + spec.retrieveOut2 + `"
    exit ` + strconv.Itoa(spec.retrieveCode2) + `
  fi
  printf '%s' "` + spec.retrieveOut + `"
  exit ` + strconv.Itoa(spec.retrieveCode) + `
  ;;
vault-enroll)
  exit ` + strconv.Itoa(spec.enrollCode) + `
  ;;
*)
  echo "unexpected verb $verb" >&2
  exit 99
  ;;
esac
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write fake helper: %v", err)
	}
	return script, logPath, argsPath
}

// writeFakeSecurity points securityBin at a script that emits out and exits code.
func writeFakeSecurity(t *testing.T, code int, out string) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "security")
	body := "#!/bin/sh\nprintf '%s' \"" + out + "\"\nexit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write fake security: %v", err)
	}
	return script
}

func readLog(t *testing.T, logPath string) []string {
	t.Helper()
	data, err := os.ReadFile(logPath) //nolint:gosec // logPath is a test-controlled temp file.
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read log: %v", err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func readBatchArgs(t *testing.T, argsPath string) []string {
	t.Helper()
	data, err := os.ReadFile(argsPath) //nolint:gosec // argsPath is a test-controlled temp file.
	if err != nil {
		t.Fatalf("read batch args: %v", err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func verbCount(lines []string, verb string) int {
	n := 0
	for _, line := range lines {
		if strings.HasPrefix(line, verb+" ") {
			n++
		}
	}
	return n
}

// reasonsFor collects the COOKIESYNC_TOUCHID_REASON each invocation of verb
// carried, in call order.
func reasonsFor(lines []string, verb string) []string {
	var reasons []string
	for _, line := range lines {
		if strings.HasPrefix(line, verb+" reason=") {
			reasons = append(reasons, strings.TrimPrefix(line, verb+" reason="))
		}
	}
	return reasons
}

// assertNoBlankPrompts fails if any prompting helper invocation — vault-retrieve
// or vault-batch-retrieve — ran without a reason, or if the blank-sheet
// vault-status probe ran at all.
func assertNoBlankPrompts(t *testing.T, lines []string) {
	t.Helper()
	if got := verbCount(lines, "vault-status"); got != 0 {
		t.Fatalf("vault-status count = %d, want 0 (the blank-sheet probe is dead)", got)
	}
	for _, verb := range []string{"vault-retrieve", "vault-batch-retrieve"} {
		for i, reason := range reasonsFor(lines, verb) {
			if reason == "" {
				t.Fatalf("%s call %d carried an empty reason", verb, i)
			}
		}
	}
}

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
			browsers: []Browser{chrome(t), arc(t)},
			reason:   "sync them across your Macs",
			want:     "unlock your Chrome + Arc cookies to sync them across your Macs",
		},
		{
			name:     "whitespace collapses like the single path",
			browsers: []Browser{chrome(t), arc(t)},
			reason:   "post   a\n\ttweet",
			want:     "unlock your Chrome + Arc cookies to post a tweet",
		},
		{
			name:     "cap truncates the reason tail never the browser names",
			browsers: []Browser{chrome(t), arc(t)},
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
		batch := ComposeBatchReason([]Browser{chrome(t)}, reason)
		single := ComposeReason("Chrome", reason)
		if batch != single {
			t.Fatalf("ComposeBatchReason(N=1, %q) = %q, want byte-identical to ComposeReason %q", reason, batch, single)
		}
	}
}

func TestObtainKeyBatchRetrievesOnceNoProbe(t *testing.T) {
	script, logPath, argsPath := writeFakeHelper(t, fakeHelperSpec{
		batchCode: 0,
		batchOut:  "0\tok\t" + b64(testPassword) + "\n",
	})
	c := TouchIDConsent{Helper: helper.Bridge{Binary: script}}

	key, err := c.ObtainKey(context.Background(), chrome(t), "post a tweet")
	if err != nil {
		t.Fatalf("ObtainKey: %v", err)
	}
	if want := DeriveKey(SafeStorageKey(testPassword)); !bytes.Equal(key, want) {
		t.Fatalf("key = %x, want %x", key, want)
	}
	lines := readLog(t, logPath)
	if got := verbCount(lines, "vault-batch-retrieve"); got != 1 {
		t.Fatalf("vault-batch-retrieve count = %d, want 1", got)
	}
	if got := verbCount(lines, "vault-retrieve"); got != 0 {
		t.Fatalf("vault-retrieve count = %d, want 0", got)
	}
	if got := verbCount(lines, "vault-enroll"); got != 0 {
		t.Fatalf("vault-enroll count = %d, want 0", got)
	}
	assertNoBlankPrompts(t, lines)
	wantReasons := []string{"unlock your Chrome cookies to post a tweet"}
	if got := reasonsFor(lines, "vault-batch-retrieve"); !slices.Equal(got, wantReasons) {
		t.Fatalf("vault-batch-retrieve reasons = %q, want %q", got, wantReasons)
	}
	wantArgs := []string{"cookiesync.vault.chrome", "Chrome Safe Storage"}
	if got := readBatchArgs(t, argsPath); !slices.Equal(got, wantArgs) {
		t.Fatalf("batch args = %q, want %q", got, wantArgs)
	}
}

func TestObtainKeysOneSheetForTwoBrowsers(t *testing.T) {
	script, logPath, argsPath := writeFakeHelper(t, fakeHelperSpec{
		batchCode: 0,
		batchOut:  "0\tok\t" + b64(testPassword) + "\n1\tok\t" + b64(testArcPassword) + "\n",
	})
	c := TouchIDConsent{Helper: helper.Bridge{Binary: script}}
	browsers := []Browser{chrome(t), arc(t)}

	outcomes, err := c.ObtainKeys(context.Background(), browsers, "sync them across your Macs")
	if err != nil {
		t.Fatalf("ObtainKeys: %v", err)
	}
	if len(outcomes) != 2 {
		t.Fatalf("outcomes = %d, want 2", len(outcomes))
	}
	for i, password := range []string{testPassword, testArcPassword} {
		if outcomes[i].Browser.Name != browsers[i].Name {
			t.Fatalf("outcome %d browser = %q, want %q", i, outcomes[i].Browser.Name, browsers[i].Name)
		}
		if outcomes[i].Missing || outcomes[i].Err != nil {
			t.Fatalf("outcome %d = %+v, want key only", i, outcomes[i])
		}
		if want := DeriveKey(SafeStorageKey(password)); !bytes.Equal(outcomes[i].Key, want) {
			t.Fatalf("outcome %d key mismatch", i)
		}
	}
	lines := readLog(t, logPath)
	if got := verbCount(lines, "vault-batch-retrieve"); got != 1 {
		t.Fatalf("vault-batch-retrieve count = %d, want 1 (one sheet for the whole batch)", got)
	}
	if got := verbCount(lines, "vault-retrieve") + verbCount(lines, "vault-enroll"); got != 0 {
		t.Fatalf("legacy verb count = %d, want 0", got)
	}
	assertNoBlankPrompts(t, lines)
	wantReasons := []string{"unlock your Chrome + Arc cookies to sync them across your Macs"}
	if got := reasonsFor(lines, "vault-batch-retrieve"); !slices.Equal(got, wantReasons) {
		t.Fatalf("vault-batch-retrieve reasons = %q, want %q", got, wantReasons)
	}
	wantArgs := []string{"cookiesync.vault.chrome", "Chrome Safe Storage", "cookiesync.vault.arc", "Arc Safe Storage"}
	if got := readBatchArgs(t, argsPath); !slices.Equal(got, wantArgs) {
		t.Fatalf("batch args = %q, want %q", got, wantArgs)
	}
}

func TestObtainKeysMissingSiblingTolerated(t *testing.T) {
	script, _, _ := writeFakeHelper(t, fakeHelperSpec{
		batchCode: 0,
		batchOut:  "0\tok\t" + b64(testPassword) + "\n1\tmissing\t-\n",
	})
	c := TouchIDConsent{Helper: helper.Bridge{Binary: script}}

	outcomes, err := c.ObtainKeys(context.Background(), []Browser{chrome(t), arc(t)}, "post a tweet")
	if err != nil {
		t.Fatalf("ObtainKeys: %v", err)
	}
	if want := DeriveKey(SafeStorageKey(testPassword)); !bytes.Equal(outcomes[0].Key, want) {
		t.Fatalf("outcome 0 key mismatch")
	}
	if outcomes[0].Missing || outcomes[0].Err != nil {
		t.Fatalf("outcome 0 = %+v, want key only", outcomes[0])
	}
	if !outcomes[1].Missing {
		t.Fatalf("outcome 1 = %+v, want Missing", outcomes[1])
	}
	if outcomes[1].Err != nil || outcomes[1].Key != nil {
		t.Fatalf("outcome 1 = %+v, want Missing only", outcomes[1])
	}
}

func TestObtainKeyMissingRaisesConsentError(t *testing.T) {
	script, _, _ := writeFakeHelper(t, fakeHelperSpec{
		batchCode: 0,
		batchOut:  "0\tmissing\t-\n",
	})
	c := TouchIDConsent{Helper: helper.Bridge{Binary: script}}

	_, err := c.ObtainKey(context.Background(), chrome(t), "post a tweet")
	var consentErr *ConsentError
	if !errors.As(err, &consentErr) {
		t.Fatalf("err = %v, want *ConsentError", err)
	}
	if !strings.Contains(consentErr.Msg, "Keychain") {
		t.Fatalf("ConsentError msg = %q, want it to mention Keychain", consentErr.Msg)
	}
}

func TestObtainKeysWholeBatchFailures(t *testing.T) {
	cases := []struct {
		name             string
		batchCode        int
		wantMsgPart      string
		wantKeybagLocked bool
	}{
		{name: "denied sheet", batchCode: 1, wantMsgPart: "cancelled or denied"},
		{name: "keybag locked is retryable", batchCode: 3, wantMsgPart: "retry after unlock", wantKeybagLocked: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script, logPath, _ := writeFakeHelper(t, fakeHelperSpec{batchCode: tc.batchCode})
			c := TouchIDConsent{Helper: helper.Bridge{Binary: script}}

			outcomes, err := c.ObtainKeys(context.Background(), []Browser{chrome(t), arc(t)}, "post a tweet")
			if outcomes != nil {
				t.Fatalf("outcomes = %+v, want nil on a whole-batch failure", outcomes)
			}
			var consentErr *ConsentError
			if !errors.As(err, &consentErr) {
				t.Fatalf("err = %v, want *ConsentError", err)
			}
			if !strings.Contains(consentErr.Msg, tc.wantMsgPart) {
				t.Fatalf("ConsentError msg = %q, want it to contain %q", consentErr.Msg, tc.wantMsgPart)
			}
			if got := errors.Is(err, ErrKeybagLocked); got != tc.wantKeybagLocked {
				t.Fatalf("errors.Is(err, ErrKeybagLocked) = %v, want %v", got, tc.wantKeybagLocked)
			}
			lines := readLog(t, logPath)
			if got := verbCount(lines, "vault-batch-retrieve"); got != 1 {
				t.Fatalf("vault-batch-retrieve count = %d, want 1", got)
			}
			if got := verbCount(lines, "vault-retrieve") + verbCount(lines, "vault-enroll"); got != 0 {
				t.Fatalf("fallback verb count = %d, want 0", got)
			}
			assertNoBlankPrompts(t, lines)
		})
	}
}

func TestObtainKeysErrorLineCarriesPerItemError(t *testing.T) {
	script, _, _ := writeFakeHelper(t, fakeHelperSpec{
		batchCode: 0,
		batchOut:  "0\tok\t" + b64(testPassword) + "\n1\terror\t-25293\n",
	})
	c := TouchIDConsent{Helper: helper.Bridge{Binary: script}}

	outcomes, err := c.ObtainKeys(context.Background(), []Browser{chrome(t), arc(t)}, "post a tweet")
	if err != nil {
		t.Fatalf("ObtainKeys: %v", err)
	}
	if want := DeriveKey(SafeStorageKey(testPassword)); !bytes.Equal(outcomes[0].Key, want) {
		t.Fatalf("outcome 0 key mismatch")
	}
	var consentErr *ConsentError
	if !errors.As(outcomes[1].Err, &consentErr) {
		t.Fatalf("outcome 1 err = %v, want *ConsentError", outcomes[1].Err)
	}
	if !strings.Contains(consentErr.Msg, "-25293") {
		t.Fatalf("ConsentError msg = %q, want it to carry OSStatus -25293", consentErr.Msg)
	}
	if outcomes[1].Missing || outcomes[1].Key != nil {
		t.Fatalf("outcome 1 = %+v, want Err only", outcomes[1])
	}
}

func TestStaleHelperFallsBackToPerBrowserRetrieve(t *testing.T) {
	script, logPath, _ := writeFakeHelper(t, fakeHelperSpec{
		batchCode:     2,
		batchStderr:   staleBatchStderr,
		retrieveCode:  0,
		retrieveOut:   testPassword,
		retrieveCode2: 0,
		retrieveOut2:  testArcPassword,
	})
	c := TouchIDConsent{Helper: helper.Bridge{Binary: script}}

	outcomes, err := c.ObtainKeys(context.Background(), []Browser{chrome(t), arc(t)}, "post a tweet")
	if err != nil {
		t.Fatalf("ObtainKeys: %v", err)
	}
	for i, password := range []string{testPassword, testArcPassword} {
		if want := DeriveKey(SafeStorageKey(password)); !bytes.Equal(outcomes[i].Key, want) {
			t.Fatalf("outcome %d key mismatch", i)
		}
	}
	lines := readLog(t, logPath)
	if got := verbCount(lines, "vault-batch-retrieve"); got != 1 {
		t.Fatalf("vault-batch-retrieve count = %d, want 1 (the stale-helper attempt)", got)
	}
	if got := verbCount(lines, "vault-retrieve"); got != 2 {
		t.Fatalf("vault-retrieve count = %d, want 2 (one per browser)", got)
	}
	assertNoBlankPrompts(t, lines)
	wantReasons := []string{
		"unlock your Chrome cookies to post a tweet",
		"unlock your Arc cookies to post a tweet",
	}
	if got := reasonsFor(lines, "vault-retrieve"); !slices.Equal(got, wantReasons) {
		t.Fatalf("vault-retrieve reasons = %q, want %q", got, wantReasons)
	}
}

func TestStaleHelperPerBrowserFailureIsolated(t *testing.T) {
	cases := []struct {
		name string
		spec fakeHelperSpec
		run  func(t *testing.T, c TouchIDConsent)
	}{
		{
			name: "sibling retrieve fails while requested succeeds",
			spec: fakeHelperSpec{
				batchCode:     2,
				batchStderr:   staleBatchStderr,
				retrieveCode:  0,
				retrieveOut:   testPassword,
				retrieveCode2: 1,
			},
			run: func(t *testing.T, c TouchIDConsent) {
				outcomes, err := c.ObtainKeys(context.Background(), []Browser{chrome(t), arc(t)}, "post a tweet")
				if err != nil {
					t.Fatalf("ObtainKeys: %v", err)
				}
				if want := DeriveKey(SafeStorageKey(testPassword)); !bytes.Equal(outcomes[0].Key, want) {
					t.Fatalf("outcome 0 key mismatch")
				}
				if outcomes[0].Missing || outcomes[0].Err != nil {
					t.Fatalf("outcome 0 = %+v, want key only", outcomes[0])
				}
				var consentErr *ConsentError
				if !errors.As(outcomes[1].Err, &consentErr) {
					t.Fatalf("outcome 1 err = %v, want *ConsentError", outcomes[1].Err)
				}
				if outcomes[1].Missing || outcomes[1].Key != nil {
					t.Fatalf("outcome 1 = %+v, want Err only", outcomes[1])
				}
			},
		},
		{
			name: "requested retrieve fails surfaces via the wrapper",
			spec: fakeHelperSpec{
				batchCode:    2,
				batchStderr:  staleBatchStderr,
				retrieveCode: 1,
			},
			run: func(t *testing.T, c TouchIDConsent) {
				_, err := c.ObtainKey(context.Background(), chrome(t), "post a tweet")
				var consentErr *ConsentError
				if !errors.As(err, &consentErr) {
					t.Fatalf("err = %v, want *ConsentError", err)
				}
				if !strings.Contains(consentErr.Msg, "cancelled or denied") {
					t.Fatalf("ConsentError msg = %q, want it to mention cancelled or denied", consentErr.Msg)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script, _, _ := writeFakeHelper(t, tc.spec)
			c := TouchIDConsent{Helper: helper.Bridge{Binary: script}}
			tc.run(t, c)
		})
	}
}

func TestStaleHelperReenrollsInvalidatedVault(t *testing.T) {
	// The stale-helper loop keeps the single-path ACL healing: the first retrieve
	// hits errSecItemNotFound (exit 2: the biometryCurrentSet ACL invalidated), so
	// it re-enrolls and retries once, preserving the reason.
	script, logPath, _ := writeFakeHelper(t, fakeHelperSpec{
		batchCode:     2,
		batchStderr:   staleBatchStderr,
		retrieveCode:  2,
		retrieveOut:   "",
		retrieveCode2: 0,
		retrieveOut2:  testPassword,
		enrollCode:    0,
	})
	c := TouchIDConsent{Helper: helper.Bridge{Binary: script}}

	key, err := c.ObtainKey(context.Background(), chrome(t), "post a tweet")
	if err != nil {
		t.Fatalf("ObtainKey: %v", err)
	}
	if want := DeriveKey(SafeStorageKey(testPassword)); !bytes.Equal(key, want) {
		t.Fatalf("key mismatch")
	}
	lines := readLog(t, logPath)
	if got := verbCount(lines, "vault-enroll"); got != 1 {
		t.Fatalf("vault-enroll count = %d, want 1", got)
	}
	if got := verbCount(lines, "vault-retrieve"); got != 2 {
		t.Fatalf("vault-retrieve count = %d, want 2 (one prompt + one ACL retry)", got)
	}
	assertNoBlankPrompts(t, lines)
	wantReasons := []string{
		"unlock your Chrome cookies to post a tweet",
		"unlock your Chrome cookies to post a tweet",
	}
	if got := reasonsFor(lines, "vault-retrieve"); !slices.Equal(got, wantReasons) {
		t.Fatalf("vault-retrieve reasons = %q, want %q", got, wantReasons)
	}
}

func TestStaleHelperEnrollFailureRaisesConsentError(t *testing.T) {
	script, logPath, _ := writeFakeHelper(t, fakeHelperSpec{
		batchCode:    2,
		batchStderr:  staleBatchStderr,
		retrieveCode: 2,
		enrollCode:   2,
	})
	c := TouchIDConsent{Helper: helper.Bridge{Binary: script}}

	_, err := c.ObtainKey(context.Background(), chrome(t), "post a tweet")
	var consentErr *ConsentError
	if !errors.As(err, &consentErr) {
		t.Fatalf("err = %v, want *ConsentError", err)
	}
	if !strings.Contains(consentErr.Msg, "enroll") {
		t.Fatalf("ConsentError msg = %q, want it to mention enroll", consentErr.Msg)
	}
	lines := readLog(t, logPath)
	if got := verbCount(lines, "vault-enroll"); got != 1 {
		t.Fatalf("vault-enroll count = %d, want 1", got)
	}
}

func TestUnavailableFallsBackToSecurityRead(t *testing.T) {
	// A genuine exit 2 — no biometry and no passcode, not the stale-helper
	// diagnostic — degrades to the bare per-browser Keychain read.
	script, logPath, _ := writeFakeHelper(t, fakeHelperSpec{
		batchCode:   2,
		batchStderr: "keyhelper: unavailable: no biometrics or passcode\n",
	})
	securityBin = writeFakeSecurity(t, 0, testPassword+"\n")
	t.Cleanup(func() { securityBin = "/usr/bin/security" })
	c := TouchIDConsent{Helper: helper.Bridge{Binary: script}}

	key, err := c.ObtainKey(context.Background(), chrome(t), "post a tweet")
	if err != nil {
		t.Fatalf("ObtainKey: %v", err)
	}
	if want := DeriveKey(SafeStorageKey(testPassword)); !bytes.Equal(key, want) {
		t.Fatalf("key mismatch")
	}
	lines := readLog(t, logPath)
	if got := verbCount(lines, "vault-retrieve") + verbCount(lines, "vault-enroll"); got != 0 {
		t.Fatalf("fallback verb count = %d, want 0", got)
	}
	assertNoBlankPrompts(t, lines)
}

func TestSecurityFallbackFailureRaises(t *testing.T) {
	script, _, _ := writeFakeHelper(t, fakeHelperSpec{
		batchCode:   2,
		batchStderr: "keyhelper: unavailable: no biometrics or passcode\n",
	})
	securityBin = writeFakeSecurity(t, 44, "")
	t.Cleanup(func() { securityBin = "/usr/bin/security" })
	c := TouchIDConsent{Helper: helper.Bridge{Binary: script}}

	_, err := c.ObtainKey(context.Background(), chrome(t), "post a tweet")
	var consentErr *ConsentError
	if !errors.As(err, &consentErr) {
		t.Fatalf("err = %v, want *ConsentError", err)
	}
	if !strings.Contains(consentErr.Msg, "Keychain") {
		t.Fatalf("ConsentError msg = %q, want it to mention Keychain", consentErr.Msg)
	}
}

func TestObtainKeyUnpromptedDoesBareSecurityReadNoTouchID(t *testing.T) {
	script, logPath, _ := writeFakeHelper(t, fakeHelperSpec{
		batchCode: 0,
		batchOut:  "0\tok\t" + b64("should-not-be-used") + "\n",
	})
	securityBin = writeFakeSecurity(t, 0, testPassword+"\n")
	t.Cleanup(func() { securityBin = "/usr/bin/security" })
	c := TouchIDConsent{Helper: helper.Bridge{Binary: script}}

	key, err := c.ObtainKeyUnprompted(context.Background(), chrome(t))
	if err != nil {
		t.Fatalf("ObtainKeyUnprompted: %v", err)
	}
	if want := DeriveKey(SafeStorageKey(testPassword)); !bytes.Equal(key, want) {
		t.Fatalf("key mismatch")
	}
	// No helper subcommand runs at all on the unprompted path.
	if lines := readLog(t, logPath); len(lines) != 0 {
		t.Fatalf("helper invoked on unprompted path: %v", lines)
	}
}

func TestObtainKeyFailsClosedWhenHelperMissing(t *testing.T) {
	// The signed helper is absent: ObtainKey fails closed via RequireHelper rather
	// than degrading to an unsigned build. The Touch ID prompt never runs.
	missing := filepath.Join(t.TempDir(), "absent", "cookiesync-keyhelper")
	restore := paths.SetHelperBinaryForTest(missing)
	t.Cleanup(restore)
	c := TouchIDConsent{} // zero-value bridge resolves via RequireHelper

	_, err := c.ObtainKey(context.Background(), chrome(t), "post a tweet")
	var helperErr *paths.HelperError
	if !errors.As(err, &helperErr) {
		t.Fatalf("err = %v, want *paths.HelperError", err)
	}
}
