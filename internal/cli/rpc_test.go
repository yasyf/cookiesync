package cli

import (
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
