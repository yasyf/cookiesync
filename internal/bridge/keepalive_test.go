package bridge

import (
	"strings"
	"testing"
)

// TestKeepaliveArgv proves the supervisor argv is ssh with hostregistry's dial
// options and brew-shellenv wrapping, targets the given addr, runs the keepalive
// command, and swaps in the sshBin seam at argv[0].
func TestKeepaliveArgv(t *testing.T) {
	seedDialAddrs(t, "you@desktop", nil)
	got, err := keepaliveArgv("you@desktop", "you@desktop")
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != sshBin {
		t.Fatalf("keepaliveArgv[0] = %q, want the sshBin seam %q", got[0], sshBin)
	}
	joined := strings.Join(got, " ")
	for _, want := range []string{
		"BatchMode=yes",
		"ServerAliveInterval=5",
		"-l you desktop",
		"cookiesync rpc bridge_keepalive",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("keepaliveArgv = %v, missing %q", got, want)
		}
	}
	// The capability is never on argv — it crosses on stdin.
	if strings.Contains(joined, "capability") {
		t.Fatalf("keepaliveArgv leaked a capability onto argv: %v", got)
	}
}
