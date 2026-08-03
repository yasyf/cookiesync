package bridge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// TestKeepaliveHoldsItsWriteSideOpen proves the supervisor's stdin survives the
// capability write. The peer reaps the proxied bridge the moment this side's
// pipe closes, so a one-shot delivery — Cmd.Stdin, which closes the pipe right
// after — would trigger the very teardown the keepalive exists to defer. The
// fake supervisor records the capability it read, then parks reading stdin and
// records again on EOF; that second marker must not appear while the keepalive
// is live.
func TestKeepaliveHoldsItsWriteSideOpen(t *testing.T) {
	seedDialAddrs(t, "you@desktop", nil)
	dir := t.TempDir()
	read := filepath.Join(dir, "read")
	eof := filepath.Join(dir, "eof")

	// The markers ride SSH_-prefixed names because bridgeEnvironment forwards
	// only its whitelist to the child.
	script := filepath.Join(dir, "fake-keepalive.sh")
	body := "#!/bin/sh\n" +
		"read -r capability || exit 1\n" +
		"printf '%s' \"$capability\" > \"$SSH_KEEPALIVE_READ\"\n" +
		"cat > /dev/null\n" +
		"printf 'eof' > \"$SSH_KEEPALIVE_EOF\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil { //nolint:gosec // an executable test fixture under the test's own temp dir.
		t.Fatalf("write fake keepalive: %v", err)
	}
	restore := sshBin
	sshBin = script
	t.Cleanup(func() { sshBin = restore })
	t.Setenv("SSH_KEEPALIVE_READ", read)
	t.Setenv("SSH_KEEPALIVE_EOF", eof)

	ctx := t.Context()
	k, err := OpenKeepalive(ctx, testSpawner(ctx, t), "you@desktop", "you@desktop", "cap-a-secret")
	if err != nil {
		t.Fatalf("OpenKeepalive: %v", err)
	}

	if got := awaitFile(t, read, 30*time.Second); got != "cap-a-secret" {
		t.Fatalf("supervisor read %q, want the capability off stdin", got)
	}
	// The write side stays open: the supervisor parks on its read rather than
	// draining to EOF, so it neither tears down nor exits while the keepalive
	// is live. A one-shot stdin delivery fails here.
	select {
	case <-k.Done():
		t.Fatal("keepalive child exited while it was meant to be held open")
	case <-time.After(time.Second):
	}
	if _, err := os.Stat(eof); !os.IsNotExist(err) {
		t.Fatalf("supervisor saw EOF while the keepalive was live: %v", err)
	}

	// Close is a teardown, not a drain: it settles the child rather than
	// waiting for it to notice the closed pipe.
	if err := k.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-k.Done():
	case <-time.After(30 * time.Second):
		t.Fatal("keepalive child never settled after Close")
	}
}

// awaitFile waits for path to hold content, returning it.
func awaitFile(t *testing.T, path string, within time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		raw, err := os.ReadFile(path) //nolint:gosec // the test's own temp marker path.
		if err == nil && len(raw) > 0 {
			return string(raw)
		}
		if time.Now().After(deadline) {
			t.Fatalf("marker %s never appeared: %v", path, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
