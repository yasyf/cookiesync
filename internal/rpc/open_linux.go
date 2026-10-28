package rpc

import (
	"context"
	"errors"
	"fmt"

	"github.com/yasyf/daemonkit/supervise"
)

// Stop drains the resident helper and removes it from the supervisor, so a
// restarted supervisor no longer resumes it. Stopping a helper that was never
// applied succeeds: daemonkit proves the observed program departed before it
// clears the inventory.
func Stop(ctx context.Context, build string) error {
	resident, err := helperClient(build)
	if err != nil {
		return err
	}
	defer closeClient(ctx, resident)
	ctx, cancel := context.WithTimeout(ctx, lifecycleBudget)
	defer cancel()
	return hint(resident.Stop(ctx))
}

func hint(err error) error {
	if errors.Is(err, supervise.ErrNoSupervisor) {
		return fmt.Errorf("%w; start 'cookiesync supervise' under the workspace process manager, then retry", err)
	}
	return err
}
