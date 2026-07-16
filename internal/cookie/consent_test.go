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
	"github.com/yasyf/synckit/authkit"
)

// Parity oracles ported from the original Python tests/cookie/test_consent.py. The
// FakeRunner there monkeypatched anyio.run_process; here a temp shell script stands
// in for the signed helper so the real subprocess boundary (argv, env, exit codes,
// binary stdin/stdout) is exercised.

const (
	testPassword    = "peanuts-safe-storage-key"
	testArcPassword = "arc-safe-storage-secret"
)

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

// fakeHelperSpec scripts a fake helper's vault-batch-retrieve exit code, stdout,
// and stderr.
type fakeHelperSpec struct {
	batchCode   int
	batchOut    string
	batchStderr string
}

// writeFakeHelper writes an executable shell script that emulates the helper's
// vault-batch-retrieve subcommand per spec, appending one line per invocation
// ("<verb> reason=<AUTHKIT_REASON>") to a log file and dumping the item args,
// one per line, to an args file. Any other verb (vault-status above all) exits
// 99, so a resurrected blank-sheet probe fails the test loudly. It returns the
// script, log, and args paths.
func writeFakeHelper(t *testing.T, spec fakeHelperSpec) (script, logPath, argsPath string) {
	t.Helper()
	dir := t.TempDir()
	script = filepath.Join(dir, "authkit")
	logPath = filepath.Join(dir, "calls.log")
	argsPath = filepath.Join(dir, "batch.args")
	body := `#!/bin/sh
verb="$1"
printf '%s reason=%s\n' "$verb" "$AUTHKIT_REASON" >> "` + logPath + `"
case "$verb" in
vault-batch-retrieve)
  shift
  printf '%s\n' "$@" > "` + argsPath + `"
  printf '%s' "` + spec.batchOut + `"
  printf '%s' "` + spec.batchStderr + `" >&2
  exit ` + strconv.Itoa(spec.batchCode) + `
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

// reasonsFor collects the AUTHKIT_REASON each invocation of verb carried, in
// call order.
func reasonsFor(lines []string, verb string) []string {
	var reasons []string
	for _, line := range lines {
		if strings.HasPrefix(line, verb+" reason=") {
			reasons = append(reasons, strings.TrimPrefix(line, verb+" reason="))
		}
	}
	return reasons
}

// assertNoBlankPrompts fails if any vault-batch-retrieve invocation ran without
// a reason, or if the blank-sheet vault-status probe ran at all.
func assertNoBlankPrompts(t *testing.T, lines []string) {
	t.Helper()
	if got := verbCount(lines, "vault-status"); got != 0 {
		t.Fatalf("vault-status count = %d, want 0 (the blank-sheet probe is dead)", got)
	}
	for i, reason := range reasonsFor(lines, "vault-batch-retrieve") {
		if reason == "" {
			t.Fatalf("vault-batch-retrieve call %d carried an empty reason", i)
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

func TestUnavailableFallsBackToSecurityRead(t *testing.T) {
	// A vault-batch-retrieve exit 2 — no biometry and no passcode — degrades to
	// the bare per-browser Keychain read.
	script, logPath, _ := writeFakeHelper(t, fakeHelperSpec{
		batchCode:   2,
		batchStderr: "authkit: unavailable: no biometrics or passcode\n",
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

func TestCallerRejectedIsHardErrorNoBareRead(t *testing.T) {
	// Exit 4 (rejected caller / usage error) must fail hard, never degrade to the
	// bare read exit 2 uses. securityBin would succeed if called, so the error proves it.
	script, logPath, _ := writeFakeHelper(t, fakeHelperSpec{
		batchCode:   authkit.CodeCallerRejected,
		batchStderr: "authkit: caller not pinned\n",
	})
	securityBin = writeFakeSecurity(t, 0, testPassword+"\n")
	t.Cleanup(func() { securityBin = "/usr/bin/security" })
	c := TouchIDConsent{Helper: helper.Bridge{Binary: script}}

	outcomes, err := c.ObtainKeys(context.Background(), []Browser{chrome(t), arc(t)}, "post a tweet")
	if outcomes != nil {
		t.Fatalf("outcomes = %+v, want nil on an exit-4 hard failure (no bare read)", outcomes)
	}
	if err == nil {
		t.Fatalf("exit 4 must surface an error, got nil")
	}
	lines := readLog(t, logPath)
	if got := verbCount(lines, "vault-batch-retrieve"); got != 1 {
		t.Fatalf("vault-batch-retrieve count = %d, want 1", got)
	}
	assertNoBlankPrompts(t, lines)
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
	missing := filepath.Join(t.TempDir(), "absent", "authkit")
	t.Setenv(authkit.HelperEnvVar, missing)
	c := TouchIDConsent{} // zero-value bridge resolves via RequireHelper

	_, err := c.ObtainKey(context.Background(), chrome(t), "post a tweet")
	var helperErr *authkit.HelperError
	if !errors.As(err, &helperErr) {
		t.Fatalf("err = %v, want *authkit.HelperError", err)
	}
}
