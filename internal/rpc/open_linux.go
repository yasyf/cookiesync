package rpc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/yasyf/daemonkit"
	"github.com/yasyf/daemonkit/supervise"

	"github.com/yasyf/cookiesync/internal/daemon"
)

const lifecycleBudget = 30 * time.Second

func open(ctx context.Context) (*daemonkit.Client, error) {
	resident, err := helperClient()
	if err != nil {
		return nil, err
	}
	if _, err := ensure(ctx, resident); err != nil {
		return nil, err
	}
	return resident, nil
}

// Ensure converges the resident helper under this workspace's running
// `cookiesync supervise`: it starts the helper, or restarts it onto this build,
// and reports what that took. With no supervisor it fails naming the command to
// start one.
func Ensure(ctx context.Context) (daemonkit.Ensured, error) {
	resident, err := helperClient()
	if err != nil {
		return daemonkit.Ensured{}, err
	}
	return ensure(ctx, resident)
}

// Stop drains the resident helper and removes it from the supervisor, so a
// restarted supervisor no longer resumes it. Stopping a helper that was never
// applied succeeds: daemonkit proves the observed program departed before it
// clears the inventory.
func Stop(ctx context.Context) error {
	resident, err := helperClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, lifecycleBudget)
	defer cancel()
	return supervisorHint(resident.Stop(ctx))
}

func helperClient() (*daemonkit.Client, error) {
	spec, err := daemon.HelperSpec()
	if err != nil {
		return nil, err
	}
	return daemonkit.Open(spec)
}

func ensure(ctx context.Context, resident *daemonkit.Client) (daemonkit.Ensured, error) {
	ctx, cancel := context.WithTimeout(ctx, lifecycleBudget)
	defer cancel()
	ensured, err := resident.Ensure(ctx)
	return ensured, supervisorHint(err)
}

func supervisorHint(err error) error {
	if errors.Is(err, supervise.ErrNoSupervisor) {
		return fmt.Errorf("%w; start 'cookiesync supervise' under the workspace process manager, then retry", err)
	}
	return err
}
