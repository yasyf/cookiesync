package helper

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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

func TestParseBatchLines(t *testing.T) {
	secret := []byte{0x00, 0xFF, 'a', '\t', '\n'}
	b64 := base64.StdEncoding.EncodeToString(secret)
	tests := []struct {
		name    string
		stdout  string
		want    []BatchLine
		wantErr string
	}{
		{
			name:   "ok line decodes the base64 secret",
			stdout: "0\tok\t" + b64 + "\n",
			want:   []BatchLine{{Index: 0, Status: BatchOK, Payload: secret}},
		},
		{
			name:   "missing line",
			stdout: "1\tmissing\t-\n",
			want:   []BatchLine{{Index: 1, Status: BatchMissing}},
		},
		{
			name:   "error line carries the OSStatus",
			stdout: "2\terror\t-25293\n",
			want:   []BatchLine{{Index: 2, Status: BatchError, OSStatus: -25293}},
		},
		{
			name:   "multiline batch keeps order and count",
			stdout: "0\tok\t" + b64 + "\n1\tmissing\t-\n2\terror\t-25308\n",
			want: []BatchLine{
				{Index: 0, Status: BatchOK, Payload: secret},
				{Index: 1, Status: BatchMissing},
				{Index: 2, Status: BatchError, OSStatus: -25308},
			},
		},
		{
			name:   "empty stdout is zero lines",
			stdout: "",
			want:   nil,
		},
		{
			name:    "two fields is malformed",
			stdout:  "0\tok\n",
			wantErr: "3 tab-separated fields",
		},
		{
			name:    "non-numeric index is malformed",
			stdout:  "x\tok\t" + b64 + "\n",
			wantErr: `index "x"`,
		},
		{
			name:    "bad base64 in an ok line is malformed",
			stdout:  "0\tok\t!!!\n",
			wantErr: `ok payload "!!!"`,
		},
		{
			name:    "unknown status is malformed",
			stdout:  "0\tdenied\t-\n",
			wantErr: `unknown status "denied"`,
		},
		{
			name:    "missing payload must be a dash",
			stdout:  "0\tmissing\tnope\n",
			wantErr: `want "-"`,
		},
		{
			name:    "error payload must be a decimal OSStatus",
			stdout:  "0\terror\tboom\n",
			wantErr: `error payload "boom"`,
		},
		{
			name:    "malformed second line names its index",
			stdout:  "0\tok\t" + b64 + "\ngarbage\n",
			wantErr: "batch line 1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseBatchLines(tt.stdout)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseBatchLines: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("lines = %#v, want %#v", got, tt.want)
			}
		})
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
