//go:build darwin

package cache

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/yasyf/cookiesync/internal/helper"
	"github.com/yasyf/synckit/authkit"
)

func TestOpenFailsClosedWhenHelperMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent", "authkit")
	t.Setenv(authkit.HelperEnvVar, missing)

	_, err := Open(context.Background(), helper.Bridge{})
	var helperErr *authkit.HelperError
	if !errors.As(err, &helperErr) {
		t.Fatalf("err = %v, want *authkit.HelperError", err)
	}
}

// TestKeyCacheOverTheSignedHelperBridge keeps the seam honest against the real
// helper.Bridge, round-tripping a key through an executable fake keyhelper.
func TestKeyCacheOverTheSignedHelperBridge(t *testing.T) {
	binary := writeFakeCacheHelper(t)
	c, err := Open(context.Background(), helper.Bridge{Binary: binary})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := c.Close(context.Background()); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	key := testKey()
	mustPut(t, c, endpoint, key)
	mustGet(t, c, endpoint, key)
	c.mu.Lock()
	blob := c.entries[endpoint].blob
	c.mu.Unlock()
	if bytes.Equal(blob, key) {
		t.Fatalf("the stored blob must not be the raw key")
	}
}

// writeFakeCacheHelper writes an executable fake keyhelper speaking the cache-*
// contract: newkey/dropkey exit 0, wrap/unwrap XOR stdin to stdout via perl.
func writeFakeCacheHelper(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "cookiesync-keyhelper")
	body := `#!/bin/sh
case "$1" in
cache-newkey|cache-dropkey)
  exit 0
  ;;
cache-wrap|cache-unwrap)
  exec /usr/bin/perl -0777 -pe 's/(.)/chr(ord($1)^0x5A)/ges'
  ;;
*)
  echo "unexpected verb $1" >&2
  exit 99
  ;;
esac
`
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write fake cache helper: %v", err)
	}
	return binary
}
