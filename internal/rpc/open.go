package rpc

import (
	"context"
	"time"

	"github.com/yasyf/daemonkit"

	"github.com/yasyf/cookiesync/internal/daemon"
)

const lifecycleBudget = 30 * time.Second

func open(ctx context.Context, build string) (*daemonkit.Client, error) {
	resident, err := helperClient(build)
	if err != nil {
		return nil, err
	}
	if _, err := ensure(ctx, resident); err != nil {
		closeClient(ctx, resident)
		return nil, err
	}
	return resident, nil
}

// Ensure converges the resident helper onto this build: it starts the helper,
// or replaces one serving another build, and reports what that took.
func Ensure(ctx context.Context, build string) (daemonkit.Ensured, error) {
	resident, err := helperClient(build)
	if err != nil {
		return daemonkit.Ensured{}, err
	}
	defer closeClient(ctx, resident)
	return ensure(ctx, resident)
}

func helperClient(build string) (*daemonkit.Client, error) {
	spec, err := daemon.HelperSpec(build)
	if err != nil {
		return nil, err
	}
	return daemonkit.Open(spec)
}

func ensure(ctx context.Context, resident *daemonkit.Client) (daemonkit.Ensured, error) {
	ctx, cancel := context.WithTimeout(ctx, lifecycleBudget)
	defer cancel()
	ensured, err := resident.Ensure(ctx)
	return ensured, hint(err)
}
