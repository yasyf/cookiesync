//go:build linux

package daemon

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestUnderivableRequestorRefusedBeforeImportLookup proves every import-serving
// method still derives the socket principal before it consults the import store: a
// caller whose session cannot be derived is refused with a live covering record in
// place, and neither the cache nor the consent gate is touched.
func TestUnderivableRequestorRefusedBeforeImportLookup(t *testing.T) {
	urls := []any{"https://app.example.test/"}
	methods := []struct {
		name   string
		method string
		params map[string]any
	}{
		{"get_cookies single", "get_cookies", map[string]any{"browser": "chrome", "profile": "Default", "urls": urls}},
		{"get_cookies union", "get_cookies", map[string]any{"urls": urls}},
		{"get_web_storage single", "get_web_storage", map[string]any{"browser": "chrome", "profile": "Default", "urls": urls}},
		{"get_web_storage union", "get_web_storage", map[string]any{"urls": urls}},
		{"bridge_open", "bridge_open", map[string]any{"browser": "chrome", "profile": "Default"}},
	}
	for _, peer := range []struct {
		name string
		pid  int
	}{
		{"peer outside the pid namespace", 0},
		{"exited peer", exitedPID(t)},
	} {
		for _, m := range methods {
			t.Run(peer.name+"/"+m.name, func(t *testing.T) {
				fakeMesh(t, importTestSelf)
				s := newImportServeDaemon(t, staticProbe(liveSession(currentUser(t))))
				s.d.imports.put(importServeKey, playwrightImportRecord(importT0.Add(time.Hour)))

				resp := dispatchAs(t, s.d.Dispatcher(), peer.pid, m.method, m.params)
				if resp.OK {
					t.Fatalf("%s served %s from the import for an underivable peer", m.method, resp.Result)
				}
				if !strings.HasPrefix(resp.Error, "cannot derive a requestor for socket peer pid "+strconv.Itoa(peer.pid)+" (") || !strings.HasSuffix(resp.Error, requestorHint) {
					t.Fatalf("%s error = %q, want the requestor refusal", m.method, resp.Error)
				}
				s.assertUntouched(t)
			})
		}
	}
}
