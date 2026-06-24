package cookie

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
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
	testVault    = "cookiesync.vault.chrome"
	testPassword = "peanuts-safe-storage-key"
)

func chrome(t *testing.T) Browser {
	t.Helper()
	b, err := Lookup(BrowserName("chrome"))
	if err != nil {
		t.Fatalf("lookup chrome: %v", err)
	}
	return b
}

// fakeHelperSpec scripts a fake helper's per-verb exit code and stdout. retrieveCode2,
// when set, is returned on the second vault-retrieve (the ACL re-enroll retry).
type fakeHelperSpec struct {
	statusCode    int
	statusOut     string
	retrieveCode  int
	retrieveOut   string
	retrieveCode2 int
	retrieveOut2  string
	enrollCode    int
}

// writeFakeHelper writes an executable shell script that emulates the helper's
// vault-* subcommands per spec, appending one line per invocation
// ("<verb> reason=<COOKIESYNC_TOUCHID_REASON>") to a log file. It returns the
// script path and the log path.
func writeFakeHelper(t *testing.T, spec fakeHelperSpec) (script, logPath string) {
	t.Helper()
	dir := t.TempDir()
	script = filepath.Join(dir, "cookiesync-keyhelper")
	logPath = filepath.Join(dir, "calls.log")
	body := `#!/bin/sh
verb="$1"
printf '%s reason=%s\n' "$verb" "$COOKIESYNC_TOUCHID_REASON" >> "` + logPath + `"
case "$verb" in
vault-status)
  printf '%s' "` + spec.statusOut + `"
  exit ` + strconv.Itoa(spec.statusCode) + `
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
	return script, logPath
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

func verbCount(lines []string, verb string) int {
	n := 0
	for _, line := range lines {
		if strings.HasPrefix(line, verb+" ") {
			n++
		}
	}
	return n
}

// assertReasonSet fails unless every vault-retrieve line carries the composed,
// non-empty reason — the Touch ID UX fix: the helper never sees its generic default.
func assertReasonSet(t *testing.T, lines []string, want string) {
	t.Helper()
	seen := false
	for _, line := range lines {
		if !strings.HasPrefix(line, "vault-retrieve ") {
			continue
		}
		seen = true
		if got := strings.TrimPrefix(line, "vault-retrieve reason="); got != want {
			t.Fatalf("vault-retrieve reason = %q, want %q", got, want)
		}
	}
	if !seen {
		t.Fatalf("no vault-retrieve invocation recorded")
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

func TestRetrieveReturnsDerivedKeyAndPromptsOnce(t *testing.T) {
	script, logPath := writeFakeHelper(t, fakeHelperSpec{
		statusCode:   0,
		statusOut:    "biometry=true passcode=true vault=true\n",
		retrieveCode: 0,
		retrieveOut:  testPassword,
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
	if got := verbCount(lines, "vault-retrieve"); got != 1 {
		t.Fatalf("vault-retrieve count = %d, want 1", got)
	}
	if got := verbCount(lines, "vault-enroll"); got != 0 {
		t.Fatalf("vault-enroll count = %d, want 0", got)
	}
	assertReasonSet(t, lines, "unlock your Chrome cookies to post a tweet")
}

func TestEnrollThenRetrieveWhenVaultMissing(t *testing.T) {
	script, logPath := writeFakeHelper(t, fakeHelperSpec{
		statusCode:   2,
		statusOut:    "biometry=true passcode=true vault=false\n",
		retrieveCode: 0,
		retrieveOut:  testPassword,
		enrollCode:   0,
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
	if got := verbCount(lines, "vault-retrieve"); got != 1 {
		t.Fatalf("vault-retrieve count = %d, want 1", got)
	}
	assertReasonSet(t, lines, "unlock your Chrome cookies to post a tweet")
}

func TestEnrollFailureRaisesConsentError(t *testing.T) {
	script, logPath := writeFakeHelper(t, fakeHelperSpec{
		statusCode:   2,
		statusOut:    "biometry=true passcode=true vault=false\n",
		retrieveCode: 0,
		retrieveOut:  testPassword,
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
	if got := verbCount(lines, "vault-retrieve"); got != 0 {
		t.Fatalf("vault-retrieve count = %d, want 0", got)
	}
}

func TestDeclineRaisesConsentError(t *testing.T) {
	script, logPath := writeFakeHelper(t, fakeHelperSpec{
		statusCode:   0,
		statusOut:    "biometry=true passcode=true vault=true\n",
		retrieveCode: 1,
	})
	c := TouchIDConsent{Helper: helper.Bridge{Binary: script}}

	_, err := c.ObtainKey(context.Background(), chrome(t), "post a tweet")
	var consentErr *ConsentError
	if !errors.As(err, &consentErr) {
		t.Fatalf("err = %v, want *ConsentError", err)
	}
	lines := readLog(t, logPath)
	if got := verbCount(lines, "vault-retrieve"); got != 1 {
		t.Fatalf("vault-retrieve count = %d, want 1", got)
	}
	assertReasonSet(t, lines, "unlock your Chrome cookies to post a tweet")
}

func TestUnavailableFallsBackToSecurityRead(t *testing.T) {
	script, logPath := writeFakeHelper(t, fakeHelperSpec{
		statusCode:   2,
		statusOut:    "biometry=false passcode=false vault=false\n",
		retrieveCode: 0,
		retrieveOut:  "should-not-be-used",
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
	if got := verbCount(lines, "vault-retrieve"); got != 0 {
		t.Fatalf("vault-retrieve count = %d, want 0", got)
	}
	if got := verbCount(lines, "vault-enroll"); got != 0 {
		t.Fatalf("vault-enroll count = %d, want 0", got)
	}
}

func TestSecurityFallbackFailureRaises(t *testing.T) {
	script, _ := writeFakeHelper(t, fakeHelperSpec{
		statusCode: 2,
		statusOut:  "biometry=false passcode=false vault=false\n",
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

func TestInvalidatedVaultReenrollsThenRetrieves(t *testing.T) {
	// status says the item exists, but the first retrieve hits errSecItemNotFound
	// (exit 2): the biometryCurrentSet ACL invalidated. ObtainKey must re-enroll
	// and retry once, preserving the reason.
	script, logPath := writeFakeHelper(t, fakeHelperSpec{
		statusCode:    0,
		statusOut:     "biometry=true passcode=true vault=true\n",
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
	assertReasonSet(t, lines, "unlock your Chrome cookies to post a tweet")
}

func TestObtainKeyUnpromptedDoesBareSecurityReadNoTouchID(t *testing.T) {
	script, logPath := writeFakeHelper(t, fakeHelperSpec{
		statusCode:   0,
		statusOut:    "biometry=true passcode=true vault=true\n",
		retrieveCode: 0,
		retrieveOut:  "should-not-be-used",
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
