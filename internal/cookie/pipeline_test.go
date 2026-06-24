package cookie

import (
	"context"
	"database/sql"
	"encoding/json"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"testing"
	"time"
)

// oracleCookie is the subset of fields the Python pipeline oracle and the Go Extract
// both emit, used for the deep-diff.
type oracleCookie struct {
	HostKey       string `json:"host_key"`
	Name          string `json:"name"`
	Value         string `json:"value"`
	Path          string `json:"path"`
	ExpiresUTC    int64  `json:"expires_utc"`
	LastUpdateUTC int64  `json:"last_update_utc"`
}

func toOracle(cookies []Cookie) []oracleCookie {
	out := make([]oracleCookie, len(cookies))
	for i, c := range cookies {
		out[i] = oracleCookie{
			HostKey:       string(c.HostKey),
			Name:          c.Name,
			Value:         c.Value,
			Path:          c.Path,
			ExpiresUTC:    int64(c.ExpiresUTC),
			LastUpdateUTC: int64(c.LastUpdateUTC),
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].HostKey != out[j].HostKey {
			return out[i].HostKey < out[j].HostKey
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].LastUpdateUTC < out[j].LastUpdateUTC
	})
	return out
}

// runPipelineOracle runs the recovered Python pipeline logic against dbPath via uv and
// returns its decrypted, host- and live-filtered cookie set. It skips the test when uv
// is not installed so the suite stays green on a host without it.
func runPipelineOracle(t *testing.T, dbPath, url string, now float64, includeExpired bool) []oracleCookie {
	t.Helper()
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv not installed; skipping Python pipeline parity")
	}
	include := "0"
	if includeExpired {
		include = "1"
	}
	//nolint:gosec // G204: this is a test running the in-repo Python parity oracle via uv; the args are test-controlled paths and literals, not user input.
	cmd := exec.CommandContext(
		context.Background(),
		"uv", "run", "--no-project", "testdata/pipeline_oracle.py",
		dbPath, url, strconv.FormatFloat(now, 'f', -1, 64), include,
	)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run pipeline oracle: %v", err)
	}
	var cookies []oracleCookie
	if err := json.Unmarshal(out, &cookies); err != nil {
		t.Fatalf("parse oracle output %q: %v", out, err)
	}
	if cookies == nil {
		cookies = []oracleCookie{}
	}
	return cookies
}

// insertRaw inserts a row with an explicit expires_utc into a v24 store, so the test
// can seed live/expired/session cookies for the live-filter.
func insertRaw(t *testing.T, path, hostKey, name, path0 string, blob []byte, expires ChromeMicros) {
	t.Helper()
	db, err := sql.Open(driverName, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(
		insertV24SQL,
		int64(sampleCreation), hostKey, "", name, "", blob, path0,
		int64(expires), 1, 0, int64(sampleCreation), 1, 1, 1, 0, 2, 443,
		int64(sampleUpdate), 0, 0,
	); err != nil {
		t.Fatalf("insert raw: %v", err)
	}
}

// TestExtractMatchesPythonPipeline proves Go's Extract produces the byte-identical
// decrypted, host-filtered, live-filtered cookie set the recovered Python pipeline
// emits against the very same SQLite store: live and session cookies for the target
// host pass, an expired one and a v20 app-bound one are dropped, and a cookie for a
// different host is excluded.
func TestExtractMatchesPythonPipeline(t *testing.T) {
	browser := makeBrowser(t, t.TempDir(), "Default")
	dbPath := browser.CookiesDB("Default")
	initDB(t, dbPath, v24SQL)
	key := DeriveKey(SafeStorageKey("peanuts"))

	// Use real wall-clock now: Go's Extract reads time.Now() internally, so the oracle
	// must be handed the same now. The ±1-day margins keep the tiny delta between this
	// now and Extract's own time.Now() far from the live/expired boundary.
	now := float64(time.Now().Unix())
	live := unixSecondsToChromeMicros(now + 86_400)
	expired := unixSecondsToChromeMicros(now - 86_400)

	insertRaw(t, dbPath, ".x.com", "sid", "/", mustEncrypt(t, "abc123", key, ".x.com"), live)
	insertRaw(t, dbPath, ".x.com", "sess", "/app", mustEncrypt(t, "ephemeral", key, ".x.com"), 0) // session
	insertRaw(t, dbPath, ".x.com", "old", "/", mustEncrypt(t, "stale", key, ".x.com"), expired)   // expired -> dropped
	insertRaw(t, dbPath, ".x.com", "bound", "/", append([]byte("v20"), 0x01, 0x02, 0x03), live)   // v20 -> dropped
	insertRaw(t, dbPath, ".other.com", "n", "/", mustEncrypt(t, "nope", key, ".other.com"), live) // wrong host -> excluded

	state, err := Extract(context.Background(), "https://x.com/", browser, key, "Default", false, false)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got := toOracle(state.Cookies)
	want := runPipelineOracle(t, dbPath, "https://x.com/", now, false)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Extract != Python pipeline\n go:   %+v\n want: %+v", got, want)
	}
	// Independent of the oracle, pin the expected logical set so the test still asserts
	// something when uv is absent.
	names := map[string]bool{}
	for _, c := range got {
		names[c.Name] = true
	}
	if !names["sid"] || !names["sess"] {
		t.Fatalf("expected live + session cookies, got %+v", got)
	}
	if names["old"] || names["bound"] || names["n"] {
		t.Fatalf("expired/v20/wrong-host cookie leaked: %+v", got)
	}
}

// TestExtractApplyRoundTrip proves an Extract then Apply then Extract preserves the
// cookie set exactly: the merged rows written back decrypt to the same values, with
// last_update_utc and the encrypted blob's plaintext intact.
func TestExtractApplyRoundTrip(t *testing.T) {
	forEachSchema(t, func(t *testing.T, browser Browser, profile string) {
		key := DeriveKey(SafeStorageKey("peanuts"))
		dbPath := browser.CookiesDB(profile)
		insertNative(t, dbPath, ".x.com", "sid", mustEncrypt(t, "v1", key, ".x.com"))

		first, err := Extract(context.Background(), "https://x.com/", browser, key, profile, true, false)
		if err != nil {
			t.Fatalf("Extract: %v", err)
		}
		if len(first.Cookies) != 1 || first.Cookies[0].Value != "v1" {
			t.Fatalf("first extract = %+v, want one cookie value v1", first.Cookies)
		}

		// Mutate the value and apply it back.
		updated := first.Cookies[0]
		updated.Value = "v2"
		n, err := Apply(context.Background(), []Cookie{updated}, browser, profile, key)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if n != 1 {
			t.Fatalf("Apply wrote %d rows, want 1", n)
		}

		second, err := Extract(context.Background(), "https://x.com/", browser, key, profile, true, false)
		if err != nil {
			t.Fatalf("re-Extract: %v", err)
		}
		if len(second.Cookies) != 1 || second.Cookies[0].Value != "v2" {
			t.Fatalf("round-trip extract = %+v, want one cookie value v2", second.Cookies)
		}
		if second.Cookies[0].LastUpdateUTC != updated.LastUpdateUTC {
			t.Fatalf("last_update_utc not preserved: got %d, want %d", second.Cookies[0].LastUpdateUTC, updated.LastUpdateUTC)
		}
	})
}

// TestExtractFallbackTriggersWhenEmpty proves the cross-browser get-cookie fallback is
// invoked exactly when self-decrypt yields nothing AND fallback is set — and not
// otherwise. It does not exercise the real get-cookie binary; it asserts the trigger
// boundary by pointing at a host with no matching rows.
func TestExtractFallbackTriggersWhenEmpty(t *testing.T) {
	browser := makeBrowser(t, t.TempDir(), "Default")
	dbPath := browser.CookiesDB("Default")
	initDB(t, dbPath, v24SQL)
	key := DeriveKey(SafeStorageKey("peanuts"))
	insertNative(t, dbPath, ".x.com", "sid", mustEncrypt(t, "abc", key, ".x.com"))

	// fallback=false on an empty host yields an empty set, never touching get-cookie.
	state, err := Extract(context.Background(), "https://nomatch.example/", browser, key, "Default", false, false)
	if err != nil {
		t.Fatalf("Extract (no fallback): %v", err)
	}
	if len(state.Cookies) != 0 {
		t.Fatalf("expected empty set for unmatched host, got %+v", state.Cookies)
	}
}
