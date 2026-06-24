package helper

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/yasyf/cookiesync/internal/paths"
)

// writeScript writes an executable shell script at a temp path and returns it.
func writeScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cookiesync-keyhelper")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil { //nolint:gosec // test fixture must be executable.
		t.Fatalf("write script: %v", err)
	}
	return path
}

func TestRunReportsExitCodeNotError(t *testing.T) {
	for _, code := range []int{0, 1, 2} {
		script := writeScript(t, "exit "+strconv.Itoa(code)+"\n")
		res, err := Bridge{Binary: script}.VaultStatus(context.Background(), "vault")
		if err != nil {
			t.Fatalf("code %d: unexpected error %v", code, err)
		}
		if res.Code != code {
			t.Fatalf("code = %d, want %d", res.Code, code)
		}
	}
}

func TestVaultRetrieveSetsReasonEnv(t *testing.T) {
	// The helper echoes COOKIESYNC_TOUCHID_REASON to stdout so we can assert the
	// bridge always sets it — the Touch ID UX fix.
	script := writeScript(t, `printf '%s' "$COOKIESYNC_TOUCHID_REASON"`+"\n")
	res, err := Bridge{Binary: script}.VaultRetrieve(context.Background(), "vault", "unlock your Chrome cookies to post a tweet")
	if err != nil {
		t.Fatalf("VaultRetrieve: %v", err)
	}
	if got := string(res.Stdout); got != "unlock your Chrome cookies to post a tweet" {
		t.Fatalf("reason env = %q", got)
	}
}

func TestCacheWrapUnwrapAreBinarySafe(t *testing.T) {
	// cache-wrap/unwrap pass raw bytes through stdin/stdout, including NULs and
	// high bytes. The fake XORs, proving the bridge does not mangle binary I/O.
	script := writeScript(t, `exec /usr/bin/perl -0777 -pe 's/(.)/chr(ord($1)^0x5A)/ges'`+"\n")
	bridge := Bridge{Binary: script}
	plaintext := []byte{0x00, 0x01, 0xFF, 0x5A, 0x80, 0x0A, 0x00}

	wrapped, err := bridge.CacheWrap(context.Background(), "label", plaintext)
	if err != nil {
		t.Fatalf("CacheWrap: %v", err)
	}
	if bytes.Equal(wrapped.Stdout, plaintext) {
		t.Fatalf("wrap was a no-op")
	}
	unwrapped, err := bridge.CacheUnwrap(context.Background(), "label", wrapped.Stdout)
	if err != nil {
		t.Fatalf("CacheUnwrap: %v", err)
	}
	if !bytes.Equal(unwrapped.Stdout, plaintext) {
		t.Fatalf("round-trip = %x, want %x", unwrapped.Stdout, plaintext)
	}
}

func TestMissingHelperFailsClosed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent", "cookiesync-keyhelper")
	restore := paths.SetHelperBinaryForTest(missing)
	t.Cleanup(restore)

	_, err := Bridge{}.VaultStatus(context.Background(), "vault")
	var helperErr *paths.HelperError
	if !errors.As(err, &helperErr) {
		t.Fatalf("err = %v, want *paths.HelperError", err)
	}
	if !strings.Contains(err.Error(), "cookiesync install") {
		t.Fatalf("HelperError = %q, want it to mention 'cookiesync install'", err.Error())
	}
}
