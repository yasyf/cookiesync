package daemon

import (
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
)

func bridgeTestProfile(t *testing.T, browser cookie.Browser) string {
	t.Helper()
	profiles, err := browser.Profiles()
	if err != nil {
		t.Fatalf("%s profiles: %v", browser.Name, err)
	}
	if len(profiles) == 0 {
		t.Skipf("skipping: no %s profiles on this host", browser.Name)
	}
	return profiles[0].Dir
}
