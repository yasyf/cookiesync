//go:build darwin

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

	"github.com/yasyf/synckit/authkit"
)

// writeScript writes an executable shell script at a temp path and returns it.
func writeScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authkit")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil { //nolint:gosec // test fixture must be executable.
		t.Fatalf("write script: %v", err)
	}
	return path
}

func TestRunReportsExitCodeNotError(t *testing.T) {
	for _, code := range []int{0, 1, 2, 3} {
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

func TestRunCapturesStderrOnCleanNonZeroExit(t *testing.T) {
	// A non-zero exit is not an error, but the helper's stderr diagnostic must
	// still reach the caller for logging/classifying.
	const diagnostic = "authkit: SecKeyCreateRandomKey failed: interaction not allowed (OSStatus -25308)"
	script := writeScript(t, "printf 'partial'\nprintf '%s\\n' \""+diagnostic+"\" >&2\nexit 3\n")
	res, err := Bridge{Binary: script}.CacheNewkey(context.Background(), "label")
	if err != nil {
		t.Fatalf("CacheNewkey: %v", err)
	}
	if res.Code != CodePresenceUnavailable {
		t.Fatalf("Code = %d, want %d", res.Code, CodePresenceUnavailable)
	}
	if got := string(res.Stderr); got != diagnostic+"\n" {
		t.Fatalf("Stderr = %q, want %q", got, diagnostic+"\n")
	}
	if got := string(res.Stdout); got != "partial" {
		t.Fatalf("Stdout = %q, want %q", got, "partial")
	}
}

func TestCacheWrapUnwrapAreBinarySafe(t *testing.T) {
	// cache-wrap/unwrap pass raw bytes through stdin/stdout; the fake XORs to
	// prove the bridge does not mangle binary I/O.
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

func TestVaultBatchRetrieveArgsAndReason(t *testing.T) {
	// The fake echoes argv to stdout and AUTHKIT_REASON to stderr, proving the
	// bridge flattens items into <vault> <safe-storage> pairs and sets the reason.
	script := writeScript(t, `printf '%s\n' "$@"`+"\n"+`printf '%s' "$AUTHKIT_REASON" >&2`+"\n")
	items := []VaultItem{
		{Vault: "cookiesync-vault-chrome", SafeStorageService: "Chrome Safe Storage"},
		{Vault: "cookiesync-vault-brave", SafeStorageService: "Brave Safe Storage"},
	}
	res, err := Bridge{Binary: script}.VaultBatchRetrieve(context.Background(), items, "unlock 2 browsers to sync")
	if err != nil {
		t.Fatalf("VaultBatchRetrieve: %v", err)
	}
	wantArgs := "vault-batch-retrieve\ncookiesync-vault-chrome\nChrome Safe Storage\ncookiesync-vault-brave\nBrave Safe Storage\n"
	if got := string(res.Stdout); got != wantArgs {
		t.Fatalf("argv = %q, want %q", got, wantArgs)
	}
	if got := string(res.Stderr); got != "unlock 2 browsers to sync" {
		t.Fatalf("reason env = %q, want %q", got, "unlock 2 browsers to sync")
	}
}

func TestMissingHelperFailsClosed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent", "authkit")
	t.Setenv(authkit.HelperEnvVar, missing)

	_, err := Bridge{}.VaultStatus(context.Background(), "vault")
	var helperErr *authkit.HelperError
	if !errors.As(err, &helperErr) {
		t.Fatalf("err = %v, want *authkit.HelperError", err)
	}
	if !strings.Contains(err.Error(), "authkit") {
		t.Fatalf("HelperError = %q, want it to mention 'authkit'", err.Error())
	}
}
