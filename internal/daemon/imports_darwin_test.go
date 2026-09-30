//go:build darwin

package daemon

import (
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
)

func TestImportIsLinuxOnly(t *testing.T) {
	self := "me@mac"
	st := stateWith(self, "", stateEndpoint(self, "chrome", "Default"))
	consent := &fakeConsent{key: cookie.AesKey("0123456789abcdef")}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	_, err := dispatchSelf(t, d, "import", map[string]any{
		"browser":  "chrome",
		"profile":  "Default",
		"format":   "playwright",
		"ttl":      "2m",
		"hosts":    []any{"app.example.test"},
		"document": `{"cookies": [], "origins": []}`,
	})
	if err == nil || err.Error() != `unknown method "import"` {
		t.Fatalf("import error = %v, want the unknown-method refusal", err)
	}
	if len(d.imports.records) != 0 {
		t.Fatalf("store holds %+v after an unknown method, want nothing", d.imports.records)
	}
	if cache.getCalls() != 0 || cache.putCalls() != 0 || len(consent.promptedReasons) != 0 || consent.biometricCalls.Load() != 0 {
		t.Fatalf("an unknown method reached the cache or consent: gets=%d puts=%d prompts=%v biometric=%d",
			cache.getCalls(), cache.putCalls(), consent.promptedReasons, consent.biometricCalls.Load())
	}
}
