package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func fakePrimeAuth(t *testing.T, park time.Duration, replies ...map[string]any) *[]float64 {
	t.Helper()
	var waits []float64
	orig := rpcCallJSON
	rpcCallJSON = func(_ context.Context, method string, params map[string]any, out any) error {
		if method != "prime_auth" {
			t.Fatalf("method = %s, want prime_auth", method)
		}
		waits = append(waits, params["wait"].(float64))
		reply := replies[min(len(waits), len(replies))-1]
		if msg, ok := reply["error"].(string); ok {
			return errors.New(msg)
		}
		time.Sleep(park)
		data, err := json.Marshal(reply)
		if err != nil {
			return err
		}
		return json.Unmarshal(data, out)
	}
	t.Cleanup(func() { rpcCallJSON = orig })
	return &waits
}

func runAuthWait(t *testing.T, wait string) (string, string, error) {
	t.Helper()
	cmd := newAuthCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--browser", "chrome", "--wait", wait})
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestAuthWaitApprovedAfterParking(t *testing.T) {
	waits := fakePrimeAuth(t, 0,
		map[string]any{"status": "waiting"},
		map[string]any{"status": "approved", "primed": true, "endpoint": "me@laptop:chrome:Default"},
	)

	stdout, stderr, err := runAuthWait(t, "10m")
	if err != nil {
		t.Fatalf("auth --wait: %v", err)
	}
	if stdout != "Authenticated me@laptop:chrome:Default.\n" || stderr != "" {
		t.Fatalf("stdout %q stderr %q, want the authenticated line alone", stdout, stderr)
	}
	if len(*waits) != 2 || (*waits)[0] > (10*time.Minute).Seconds() || (*waits)[1] > (*waits)[0] {
		t.Fatalf("wait params = %v, want two calls carrying the shrinking remainder of 10m", *waits)
	}
}

func TestAuthWaitDeniedExitsWithItsCode(t *testing.T) {
	fakePrimeAuth(t, 0, map[string]any{"status": "denied", "reason": "consent denied from you@desktop"})

	_, stderr, err := runAuthWait(t, "10m")
	var status statusError
	if !errors.As(err, &status) || int(status) != authDeniedExit {
		t.Fatalf("auth --wait err = %v, want exit %d", err, authDeniedExit)
	}
	if stderr != "cookiesync: consent denied from you@desktop\n" {
		t.Fatalf("stderr = %q, want the one-line denial", stderr)
	}
}

func TestAuthWaitTimesOutWithItsCode(t *testing.T) {
	waits := fakePrimeAuth(t, 10*time.Millisecond, map[string]any{"status": "waiting"})

	_, stderr, err := runAuthWait(t, "50ms")
	var status statusError
	if !errors.As(err, &status) || int(status) != authTimeoutExit {
		t.Fatalf("auth --wait err = %v, want exit %d", err, authTimeoutExit)
	}
	if !strings.HasPrefix(stderr, "cookiesync: no Mac with a live session came up to approve within 50ms") || strings.Count(stderr, "\n") != 1 {
		t.Fatalf("stderr = %q, want the one-line timeout", stderr)
	}
	if len(*waits) < 2 {
		t.Fatalf("prime_auth calls = %d, want the wait chained across several", len(*waits))
	}
}

func TestAuthWaitPropagatesADaemonFailure(t *testing.T) {
	fakePrimeAuth(t, 0, map[string]any{"error": "parse presence from you@desktop: invalid character"})

	_, _, err := runAuthWait(t, "10m")
	var status statusError
	if err == nil || errors.As(err, &status) || !strings.Contains(err.Error(), "parse presence") {
		t.Fatalf("auth --wait err = %v, want the daemon failure verbatim", err)
	}
}
