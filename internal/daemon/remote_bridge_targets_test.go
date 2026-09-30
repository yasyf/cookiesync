package daemon

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

func TestRemoteBridgeOpenForwardsTheWindowMode(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		suffix string
	}{
		{name: "auto leaves the window to the peer", params: map[string]any{}, suffix: ""},
		{name: "headed", params: map[string]any{"headed": true}, suffix: " --headed"},
		{name: "headless", params: map[string]any{"headed": false}, suffix: " --headless"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &recordingRunner{byMethod: map[string]string{"bridge_open": cannedBridgeOpenReply}}
			d, _, _ := newProxyDaemon(t, runner)
			t.Cleanup(func() { d.closeAllBridges(context.Background()) })

			params := map[string]any{"browser": "chrome", "host": "you@desktop"}
			for k, v := range tt.params {
				params[k] = v
			}
			if _, err := dispatchSelf(t, d, "bridge_open", params); err != nil {
				t.Fatalf("cross-host bridge_open %v: %v", tt.params, err)
			}
			want := regexp.MustCompile(`^cookiesync rpc bridge_open --browser 'chrome' --profile 'Default' --origin 'me@laptop' --advertise '127\.0\.0\.1:[0-9]+'` +
				regexp.QuoteMeta(tt.suffix) + `$`)
			if shelled := shelledCmd(t, runner, "bridge_open"); !want.MatchString(shelled) {
				t.Fatalf("shelled bridge_open = %q, want it to match %s", shelled, want)
			}
		})
	}
}

func TestRemoteBridgeOpenAcceptsAnyPlatformsBrowser(t *testing.T) {
	runner := &recordingRunner{byMethod: map[string]string{"bridge_open": strings.ReplaceAll(cannedBridgeOpenReply, "chrome", "arc")}}
	d, _, _ := newProxyDaemon(t, runner)
	t.Cleanup(func() { d.closeAllBridges(context.Background()) })

	if _, err := dispatchSelf(t, d, "bridge_open", map[string]any{"browser": "arc", "host": "you@desktop"}); err != nil {
		t.Fatalf("cross-host bridge_open of the peer's arc: %v", err)
	}
	if shelled := shelledCmd(t, runner, "bridge_open"); !strings.Contains(shelled, "--browser 'arc'") {
		t.Fatalf("shelled bridge_open = %q, want --browser 'arc'", shelled)
	}
}

func TestRemoteBridgeOpenRejectsABrowserNoPlatformRegisters(t *testing.T) {
	runner := &recordingRunner{byMethod: map[string]string{"bridge_open": cannedBridgeOpenReply}}
	d, _, _ := newProxyDaemon(t, runner)

	_, err := dispatchSelf(t, d, "bridge_open", map[string]any{"browser": "nosuch", "host": "you@desktop"})
	if err == nil || err.Error() != `unknown browser "nosuch"` {
		t.Fatalf("cross-host bridge_open of an unknown browser = %v, want unknown browser \"nosuch\"", err)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.calls) != 0 {
		t.Fatalf("an unknown browser still shelled ssh: %+v", runner.calls)
	}
}
