//go:build linux

package auth

import (
	"fmt"

	"github.com/yasyf/cookiesync/internal/cookie"
)

// unroutableBrowserError refuses to route consent for a browser no Mac approver
// holds: the handshake forwards the browser name unchanged and the approver
// resolves it in its own registry, so a name Darwin never registers would end
// in a fatal unknown-browser reply, never an approval.
type unroutableBrowserError struct {
	browser cookie.BrowserName
}

func (e *unroutableBrowserError) Error() string {
	return fmt.Sprintf("browser %q cannot route consent: no Mac approver registers it", e.browser)
}

func routable(browser cookie.Browser) error {
	if !browser.ConsentRoutable {
		return &unroutableBrowserError{browser: browser.Name}
	}
	return nil
}
