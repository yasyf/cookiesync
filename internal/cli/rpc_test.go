package cli

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
)

// TestRPCGetCookiesRejectsEmptyBrowser proves the recursion guard is airtight against a
// bare --browser "": MarkFlagRequired only proves the flag was set, so an explicit empty
// value must be rejected before it reaches the daemon, where it would take the union
// branch and re-fan-out over ssh.
func TestRPCGetCookiesRejectsEmptyBrowser(t *testing.T) {
	cmd := newRPCGetCookiesCmd()
	cmd.SetArgs([]string{"--browser", "", "https://x.com"})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--browser must not be empty") {
		t.Fatalf("rpc get_cookies --browser '' = %v, want '--browser must not be empty'", err)
	}
}

func TestRPCBridgeOpenForwardsTheWindowMode(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		headed any
	}{
		{name: "neither flag leaves the window to the daemon"},
		{name: "headed", args: []string{"--headed"}, headed: true},
		{name: "headless", args: []string{"--headless"}, headed: false},
		{name: "headed false", args: []string{"--headed=false"}, headed: false},
		{name: "headless false", args: []string{"--headless=false"}},
		{name: "headless wins over headed", args: []string{"--headed", "--headless"}, headed: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotMethod string
			var gotParams map[string]any
			orig := rpcCall
			rpcCall = func(_ context.Context, method string, params map[string]any) (any, error) {
				gotMethod, gotParams = method, params
				return map[string]any{}, nil
			}
			t.Cleanup(func() { rpcCall = orig })

			cmd := newRPCBridgeOpenCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs(append([]string{"--browser", "chrome"}, tt.args...))
			if err := cmd.Execute(); err != nil {
				t.Fatalf("rpc bridge_open %v: %v\n%s", tt.args, err, out.String())
			}
			want := map[string]any{"host": "", "browser": "chrome", "profile": "Default", "origin": "", "advertise": ""}
			if tt.headed != nil {
				want["headed"] = tt.headed
			}
			if gotMethod != "bridge_open" || !reflect.DeepEqual(gotParams, want) {
				t.Fatalf("rpc bridge_open %v called %s %v, want bridge_open %v", tt.args, gotMethod, gotParams, want)
			}
		})
	}
}
