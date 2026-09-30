package daemon

import (
	"os"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
)

func bridgeTestProfile(t *testing.T, browser cookie.Browser) string {
	t.Helper()
	const profile = "Default"
	if err := os.MkdirAll(browser.ProfileDir(profile), 0o700); err != nil {
		t.Fatalf("mkdir profile: %v", err)
	}
	if err := os.WriteFile(browser.CookiesDB(profile), nil, 0o600); err != nil {
		t.Fatalf("write cookie store: %v", err)
	}
	return profile
}
