//go:build darwin

package daemon

import (
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/helper"
	"github.com/yasyf/synckit/presence"
)

// consentReason is the default Touch ID prompt reason for a prime_auth with no
// caller-supplied reason — the frozen wording the Python daemon uses.
const consentReason = "sync them across your Macs"

func hostPlatform() platform {
	return platform{
		sealer:  helper.Bridge{},
		consent: cookie.TouchIDConsent{},
		session: presence.Session,
		// keybag_locked derives from the console session alone: the ioreg-only
		// probe keeps netstat off the doctor hot path.
		keybag: presence.Console,
	}
}
