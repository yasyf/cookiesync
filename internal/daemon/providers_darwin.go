//go:build darwin

package daemon

import (
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/yasyf/daemonkit"
	"github.com/yasyf/synckit/helperruntime"
	"github.com/yasyf/synckit/presence"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/helper"
	"github.com/yasyf/cookiesync/internal/paths"
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

// HelperSpec is the resident helper's daemonkit identity as launchd runs it:
// the label every client opens, the helper-serve role, and the Homebrew link
// PATH resolves, which survives the upgrade that deletes the versioned
// CookieSync.app it points into and keeps the bundle identity TCC grants key on.
func HelperSpec(build string) (daemonkit.Daemon, error) {
	alias, err := exec.LookPath(paths.ToolName)
	if err != nil {
		return daemonkit.Daemon{}, fmt.Errorf("resolve %s on PATH: %w", paths.ToolName, err)
	}
	alias, err = filepath.Abs(alias)
	if err != nil {
		return daemonkit.Daemon{}, fmt.Errorf("resolve %s on PATH: %w", paths.ToolName, err)
	}
	program, err := daemonkit.Installed(alias, build)
	if err != nil {
		return daemonkit.Daemon{}, err
	}
	spec, err := helperruntime.Spec(paths.ToolName, program, 0)
	if err != nil {
		return daemonkit.Daemon{}, err
	}
	spec.Args = []string{helperCommand}
	return spec, nil
}
