//go:build linux

package daemon

import (
	"context"

	"github.com/yasyf/daemonkit"
	"github.com/yasyf/synckit/helperruntime"

	"github.com/yasyf/cookiesync/internal/cache"
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/paths"
)

// consentReason is the default consent reason for a prime_auth with no
// caller-supplied reason.
const consentReason = "sync them across your machines"

// helperCommand is the cookiesync subcommand the supervisor runs as the
// resident helper.
const helperCommand = "helper-serve"

func hostPlatform() platform {
	return platform{
		sealer:  cache.NoEnclave{},
		consent: cookie.LinuxConsent{},
		session: unattended,
		keybag:  unattended,
	}
}

// unattended must succeed: a probe error makes the broker treat this host as
// attended and take the local-prompt branch, and an attended snapshot makes a
// peer pick this host as a consent approver.
func unattended(context.Context) (SessionSnapshot, error) {
	return SessionSnapshot{}, nil
}

// HelperSpec is the resident helper's daemonkit identity as a Linux supervisor
// runs it: the label every client opens, the stable program path, and the
// helper-serve role. It is the spec daemonkit.Supervise is keyed by and
// Client.Ensure applies.
func HelperSpec() (daemonkit.Daemon, error) {
	program, err := daemonkit.Stable()
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
