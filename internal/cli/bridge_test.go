package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
)

// stubOpenBridge swaps the openBridge seam for the duration of a test.
func stubOpenBridge(t *testing.T, fn func(context.Context, string, string, string, bool) (bridgeOpenResult, error)) {
	t.Helper()
	orig := openBridge
	openBridge = fn
	t.Cleanup(func() { openBridge = orig })
}

// stubStopBridge swaps the stopBridge seam for the duration of a test.
func stubStopBridge(t *testing.T, fn func(context.Context, string) error) {
	t.Helper()
	orig := stopBridge
	stopBridge = fn
	t.Cleanup(func() { stopBridge = orig })
}

// TestBridgeOpenJSON proves `bridge open --json` emits exactly the capability-free
// bridgeOpenJSON object (no human lines), carries the url, and never leaks the
// management capability openBridge persists client-side.
func TestBridgeOpenJSON(t *testing.T) {
	stubOpenBridge(t, func(_ context.Context, host, browser, profile string, headed bool) (bridgeOpenResult, error) {
		if host != "" || browser != "chrome" || profile != bridgeDefaultProfile || !headed {
			t.Fatalf("openBridge args = %q/%q/%q headed=%v, want ''/chrome/Default headed=true", host, browser, profile, headed)
		}
		return bridgeOpenResult{
			URL:        "ws://127.0.0.1:9222/devtools/browser/tok",
			Endpoint:   "me@laptop:chrome:Default",
			Browser:    "chrome",
			Profile:    "Default",
			Capability: "cap-xyz",
			ExpiresIn:  300,
		}, nil
	})

	cmd := newBridgeOpenCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--json", "chrome"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("bridge open --json: %v\n%s", err, out.String())
	}

	assertNoCapability(t, out.String())

	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("bridge open --json is not valid JSON: %v\n%s", err, out.String())
	}
	assertExactKeys(t, "bridge open --json", got, "protocol_version", "url", "endpoint", "browser", "profile", "expires_in")
	if got["protocol_version"] != float64(cookie.ProtocolVersion) {
		t.Fatalf("bridge open --json protocol_version = %v, want %d", got["protocol_version"], cookie.ProtocolVersion)
	}
	if got["url"] != "ws://127.0.0.1:9222/devtools/browser/tok" {
		t.Fatalf("bridge open --json url = %v, want the ws endpoint: %s", got["url"], out.String())
	}
	// No human "bridge ready" line leaks alongside the JSON.
	if strings.Contains(out.String(), "bridge ready") {
		t.Fatalf("bridge open --json leaked a human line: %s", out.String())
	}
}

func TestBridgeCapabilityStateUsesExactV1(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	const key = ":chrome:Default"
	if err := saveCap(key, "cap-v1"); err != nil {
		t.Fatalf("saveCap: %v", err)
	}
	path, err := capFile(key)
	if err != nil {
		t.Fatalf("capFile: %v", err)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: capFile returns a sha256 name under the test config dir.
	if err != nil {
		t.Fatalf("read capability: %v", err)
	}
	want := fmt.Sprintf(
		`{"schema":{"identity":%q,"version":1,"fingerprint":%q},"target":%q,"capability":"cap-v1"}`,
		capStateIdentity,
		capStateFingerprint,
		key,
	)
	if string(raw) != want {
		t.Fatalf("capability state = %s, want exact v1 envelope", raw)
	}
	if got, ok, err := loadCap(key); err != nil || !ok || got != "cap-v1" {
		t.Fatalf("loadCap = %q/%v/%v, want cap-v1/true/nil", got, ok, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat capability: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("capability mode = %#o, want 0600", got)
	}
	dir, err := capsDir()
	if err != nil {
		t.Fatalf("capsDir: %v", err)
	}
	info, err = os.Stat(dir)
	if err != nil {
		t.Fatalf("stat caps dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("caps dir mode = %#o, want 0700", got)
	}
}

func TestInvalidBridgeCapabilityStateFailsLoudlyAndRemains(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	const key = ":chrome:Default"
	path, err := capFile(key)
	if err != nil {
		t.Fatalf("capFile: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create caps dir: %v", err)
	}
	schema := func(identity string, version uint64, fingerprint string) string {
		return fmt.Sprintf(`{"identity":%q,"version":%d,"fingerprint":%q}`, identity, version, fingerprint)
	}
	state := func(schemaJSON, target, capability string) string {
		return fmt.Sprintf(`{"schema":%s,"target":%q,"capability":%q}`, schemaJSON, target, capability)
	}
	exactSchema := schema(capStateIdentity, capStateVersion, capStateFingerprint)
	valid := state(exactSchema, key, "cap-v1")

	cases := map[string]string{
		"corrupt":              "not-json",
		"legacy plaintext":     "legacy-plaintext-capability",
		"legacy envelope":      `{"protocol_version":1,"capability":"cap-old"}`,
		"foreign identity":     state(schema("other-state-v1", capStateVersion, capStateFingerprint), key, "cap-v1"),
		"wrong version":        state(schema(capStateIdentity, 2, capStateFingerprint), key, "cap-v1"),
		"wrong fingerprint":    state(schema(capStateIdentity, capStateVersion, "wrong"), key, "cap-v1"),
		"unknown top key":      strings.TrimSuffix(valid, "}") + `,"legacy":true}`,
		"unknown schema key":   state(strings.TrimSuffix(exactSchema, "}")+`,"legacy":true}`, key, "cap-v1"),
		"missing schema":       fmt.Sprintf(`{"target":%q,"capability":"cap-v1"}`, key),
		"missing target":       fmt.Sprintf(`{"schema":%s,"capability":"cap-v1"}`, exactSchema),
		"missing capability":   fmt.Sprintf(`{"schema":%s,"target":%q}`, exactSchema, key),
		"null target":          fmt.Sprintf(`{"schema":%s,"target":null,"capability":"cap-v1"}`, exactSchema),
		"trailing json":        valid + `{}`,
		"duplicate capability": strings.TrimSuffix(valid, "}") + `,"capability":"other"}`,
		"different target":     state(exactSchema, "remote:chrome:Default", "cap-v1"),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatalf("write invalid capability: %v", err)
			}
			if got, ok, err := loadCap(key); err == nil || ok || got != "" {
				t.Fatalf("loadCap = %q/%v/%v, want empty/false/error", got, ok, err)
			}
			got, err := os.ReadFile(path) //nolint:gosec // G304: capFile returns a hash under the test config dir.
			if err != nil {
				t.Fatalf("invalid capability was removed: %v", err)
			}
			if string(got) != raw {
				t.Fatalf("invalid capability changed: got %q, want %q", got, raw)
			}
		})
	}

	const invalid = "not-json"
	if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
		t.Fatalf("write invalid capability: %v", err)
	}
	if _, err := openBridge(t.Context(), "", "chrome", bridgeDefaultProfile, false); err == nil {
		t.Fatal("openBridge accepted invalid persisted capability")
	}
	if err := stopBridge(t.Context(), key); err == nil {
		t.Fatal("stopBridge accepted invalid persisted capability")
	}
	if _, err := listCaps(); err == nil {
		t.Fatal("listCaps accepted invalid persisted capability")
	}
	got, err := os.ReadFile(path) //nolint:gosec // G304: capFile returns a hash under the test config dir.
	if err != nil {
		t.Fatalf("invalid capability was removed by an operation: %v", err)
	}
	if string(got) != invalid {
		t.Fatalf("invalid capability changed by an operation: got %q, want %q", got, invalid)
	}
}

func TestBridgeCapabilityStateRejectsInsecureModeWithoutDeletion(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	const key = ":chrome:Default"
	if err := saveCap(key, "cap-v1"); err != nil {
		t.Fatalf("saveCap: %v", err)
	}
	path, err := capFile(key)
	if err != nil {
		t.Fatalf("capFile: %v", err)
	}
	// #nosec G302 -- deliberately weaken the fixture to verify fail-closed loading.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod capability: %v", err)
	}
	if got, ok, err := loadCap(key); err == nil || ok || got != "" {
		t.Fatalf("loadCap = %q/%v/%v, want empty/false/error", got, ok, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("insecure capability was removed: %v", err)
	}
}

// TestBridgePluginManifest pins the plugin.manifest response to exactly its
// envelope + descriptor keys and asserts no capability leaks.
func TestBridgePluginManifest(t *testing.T) {
	out := runPlugin(t, `{"protocol":"agent-browser.plugin.v1","type":"plugin.manifest"}`)
	assertNoCapability(t, out)

	var top map[string]any
	if err := json.Unmarshal([]byte(out), &top); err != nil {
		t.Fatalf("manifest response is not valid JSON: %v\n%s", err, out)
	}
	assertExactKeys(t, "manifest envelope", top, "protocol", "success", "manifest")
	if top["protocol"] != agentBrowserProtocol || top["success"] != true {
		t.Fatalf("manifest envelope = %v, want protocol=%s success=true", top, agentBrowserProtocol)
	}
	manifest, ok := top["manifest"].(map[string]any)
	if !ok {
		t.Fatalf("manifest is not an object: %s", out)
	}
	assertExactKeys(t, "manifest descriptor", manifest, "name", "capabilities", "description")
	if manifest["name"] != "cookiesync" {
		t.Fatalf("manifest name = %q, want cookiesync", manifest["name"])
	}
	caps, ok := manifest["capabilities"].([]any)
	if !ok || len(caps) != 1 || caps[0] != "browser.provider" {
		t.Fatalf("manifest capabilities = %v, want [browser.provider]", manifest["capabilities"])
	}
	if manifest["description"] == "" {
		t.Fatal("manifest description is empty")
	}
}

// TestBridgePluginLaunch proves browser.launch returns exactly {protocol, success,
// browser} with cdpUrl byte-for-byte, directPage=false, and the client-side cleanup
// key :chrome:Default — never the capability openBridge returned.
func TestBridgePluginLaunch(t *testing.T) {
	var gotHost, gotBrowser, gotProfile string
	var gotHeaded bool
	stubOpenBridge(t, func(_ context.Context, host, browser, profile string, headed bool) (bridgeOpenResult, error) {
		gotHost, gotBrowser, gotProfile, gotHeaded = host, browser, profile, headed
		return bridgeOpenResult{
			URL:        "ws://127.0.0.1:9222/devtools/browser/tok",
			Endpoint:   "me@laptop:chrome:Default",
			Capability: "cap-secret",
		}, nil
	})

	req := `{"protocol":"agent-browser.plugin.v1","type":"browser.launch","capability":"browser.provider",` +
		`"request":{"provider":"cookiesync","session":"default","launchOptions":{"headed":true,"engine":"chrome"}}}`
	out := runPlugin(t, req)
	assertNoCapability(t, out)

	var top map[string]any
	if err := json.Unmarshal([]byte(out), &top); err != nil {
		t.Fatalf("launch response is not valid JSON: %v\n%s", err, out)
	}
	assertExactKeys(t, "launch envelope", top, "protocol", "success", "browser")
	if top["protocol"] != agentBrowserProtocol || top["success"] != true {
		t.Fatalf("launch envelope = %v, want protocol=%s success=true", top, agentBrowserProtocol)
	}
	browser, ok := top["browser"].(map[string]any)
	if !ok {
		t.Fatalf("launch browser is not an object: %s", out)
	}
	assertExactKeys(t, "launch browser", browser, "cdpUrl", "directPage", "cleanup")
	if browser["cdpUrl"] != "ws://127.0.0.1:9222/devtools/browser/tok" {
		t.Fatalf("launch cdpUrl = %q, want the ws endpoint byte-for-byte", browser["cdpUrl"])
	}
	if browser["directPage"] != false {
		t.Fatal("launch directPage = true, want false so agent-browser runs its own target discovery")
	}
	cleanup, ok := browser["cleanup"].(map[string]any)
	if !ok {
		t.Fatalf("launch cleanup is not an object: %s", out)
	}
	assertExactKeys(t, "launch cleanup", cleanup, "endpoint")
	if cleanup["endpoint"] != ":chrome:Default" {
		t.Fatalf("launch cleanup endpoint = %q, want the client key :chrome:Default", cleanup["endpoint"])
	}
	if gotHost != "" || gotBrowser != "chrome" || gotProfile != bridgeDefaultProfile || !gotHeaded {
		t.Fatalf("openBridge got %q/%q/%q headed=%v, want ''/chrome/Default headed=true", gotHost, gotBrowser, gotProfile, gotHeaded)
	}
}

// TestBridgePluginLaunchBadEngine proves an empty or unknown engine yields a
// success:false envelope and exit 0 (nil return) without opening a bridge — no
// silent chrome default.
func TestBridgePluginLaunchBadEngine(t *testing.T) {
	for _, engine := range []string{"", "lightpanda", "firefox"} {
		t.Run("engine="+engine, func(t *testing.T) {
			stubOpenBridge(t, func(context.Context, string, string, string, bool) (bridgeOpenResult, error) {
				t.Fatal("a bad engine must not open a bridge")
				return bridgeOpenResult{}, nil
			})
			req := `{"protocol":"agent-browser.plugin.v1","type":"browser.launch","request":{"launchOptions":{"engine":"` + engine + `"}}}`
			out := runPlugin(t, req)

			var resp map[string]any
			if err := json.Unmarshal([]byte(out), &resp); err != nil {
				t.Fatalf("bad-engine response is not valid JSON: %v\n%s", err, out)
			}
			if resp["success"] != false {
				t.Fatalf("bad-engine envelope = %v, want success=false", resp)
			}
			if !strings.Contains(resp["error"].(string), "engine") {
				t.Fatalf("bad-engine error = %v, want it to name the engine", resp["error"])
			}
		})
	}
}

// TestBridgePluginLaunchError proves a daemon-side open failure surfaces as a
// success:false envelope carrying the error and exit 0 (nil return) — a valid
// protocol response is a successful program run.
func TestBridgePluginLaunchError(t *testing.T) {
	stubOpenBridge(t, func(_ context.Context, _, _, _ string, _ bool) (bridgeOpenResult, error) {
		return bridgeOpenResult{}, errBoom
	})
	req := `{"protocol":"agent-browser.plugin.v1","type":"browser.launch","request":{"launchOptions":{"engine":"chrome"}}}`
	out := runPlugin(t, req)

	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("error response is not valid JSON: %v\n%s", err, out)
	}
	if resp["protocol"] != agentBrowserProtocol || resp["success"] != false {
		t.Fatalf("launch error envelope = %v, want protocol=%s success=false", resp, agentBrowserProtocol)
	}
	if !strings.Contains(resp["error"].(string), "boom") {
		t.Fatalf("launch error message = %v, want it to carry the cause", resp["error"])
	}
}

// TestBridgePluginClose proves browser.close routes the echoed cleanup endpoint
// through the shared stopBridge seam, replies exactly {protocol, success}, and
// leaks no capability.
func TestBridgePluginClose(t *testing.T) {
	var gotKey string
	stubStopBridge(t, func(_ context.Context, key string) error {
		gotKey = key
		return nil
	})
	req := `{"protocol":"agent-browser.plugin.v1","type":"browser.close","request":{"endpoint":":chrome:Default"}}`
	out := runPlugin(t, req)
	assertNoCapability(t, out)

	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("close response is not valid JSON: %v\n%s", err, out)
	}
	assertExactKeys(t, "close envelope", resp, "protocol", "success")
	if resp["protocol"] != agentBrowserProtocol || resp["success"] != true {
		t.Fatalf("close envelope = %v, want protocol=%s success=true", resp, agentBrowserProtocol)
	}
	if gotKey != ":chrome:Default" {
		t.Fatalf("stopBridge got key %q, want the echoed :chrome:Default", gotKey)
	}
}

// TestBridgePluginUnknownType proves an unrecognized type yields a success:false
// envelope and exit 0 (nil return), without touching a bridge.
func TestBridgePluginUnknownType(t *testing.T) {
	stubOpenBridge(t, func(context.Context, string, string, string, bool) (bridgeOpenResult, error) {
		t.Fatal("unknown type must not open a bridge")
		return bridgeOpenResult{}, nil
	})
	out := runPlugin(t, `{"protocol":"agent-browser.plugin.v1","type":"browser.teleport"}`)

	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("unknown-type response is not valid JSON: %v\n%s", err, out)
	}
	if resp["success"] != false {
		t.Fatalf("unknown-type envelope = %v, want success=false", resp)
	}
	if !strings.Contains(resp["error"].(string), "browser.teleport") {
		t.Fatalf("unknown-type error = %v, want it to name the type", resp["error"])
	}
}

// TestBridgePluginBadProtocol proves a mismatched protocol tag yields a
// success:false envelope and exit 0 (nil return), not a panic or non-zero exit.
func TestBridgePluginBadProtocol(t *testing.T) {
	stubOpenBridge(t, func(context.Context, string, string, string, bool) (bridgeOpenResult, error) {
		t.Fatal("a bad protocol must not open a bridge")
		return bridgeOpenResult{}, nil
	})
	out := runPlugin(t, `{"protocol":"agent-browser.plugin.v99","type":"browser.launch"}`)

	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("bad-protocol response is not valid JSON: %v\n%s", err, out)
	}
	if resp["success"] != false {
		t.Fatalf("bad-protocol envelope = %v, want success=false", resp)
	}
	if !strings.Contains(resp["error"].(string), "protocol") {
		t.Fatalf("bad-protocol error = %v, want it to name the protocol", resp["error"])
	}
}

// errBoom is a sentinel error a stubbed openBridge returns to simulate a launch
// failure.
var errBoom = &stubError{"boom"}

type stubError struct{ msg string }

func (e *stubError) Error() string { return e.msg }

// runPlugin feeds req to runBridgePlugin, asserts it exits 0 (nil return — a valid
// protocol response is a successful run), and returns its stdout.
func runPlugin(t *testing.T, req string) string {
	t.Helper()
	var out bytes.Buffer
	if err := runBridgePlugin(context.Background(), strings.NewReader(req), &out); err != nil {
		t.Fatalf("runBridgePlugin(%s) = %v, want nil", req, err)
	}
	return out.String()
}

// assertExactKeys fails unless m carries exactly the want keys.
func assertExactKeys(t *testing.T, label string, m map[string]any, want ...string) {
	t.Helper()
	if len(m) != len(want) {
		t.Fatalf("%s keys = %v, want exactly %v", label, keysOf(m), want)
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Fatalf("%s missing key %q; keys = %v, want %v", label, k, keysOf(m), want)
		}
	}
}

// assertNoCapability fails if raw carries a capability field or a cap- secret,
// which the plugin and `bridge open --json` must never write to stdout.
func assertNoCapability(t *testing.T, raw string) {
	t.Helper()
	if strings.Contains(raw, "capability") || strings.Contains(raw, "cap-") {
		t.Fatalf("output leaked a capability: %s", raw)
	}
}

func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
