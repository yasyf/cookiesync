package bridge

import (
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/yasyf/daemonkit"
)

const childSettlementTimeout = 10 * time.Second

// Spawner starts one long-lived owned child under a durable process-ownership
// scope. Both daemonkit.Ctx (a daemon's scope) and *daemonkit.Owned (a CLI's)
// satisfy it.
type Spawner interface {
	Spawn(ctx context.Context, cmd daemonkit.Cmd, channel daemonkit.Channel, stderr io.Writer) (*daemonkit.Child, error)
}

func bridgeEnvironment() []string {
	keys := map[string]string{}
	for _, variable := range os.Environ() {
		key, _, ok := strings.Cut(variable, "=")
		if !ok || key == "PATH" || key == "LANG" {
			continue
		}
		if key == "HOME" || key == "USER" || key == "LOGNAME" || key == "TMPDIR" || key == "XDG_CONFIG_HOME" ||
			strings.HasPrefix(key, "COOKIESYNC_") || strings.HasPrefix(key, "SSH_") {
			keys[key] = variable
		}
	}
	environment := make([]string, 0, len(keys))
	for _, variable := range keys {
		environment = append(environment, variable)
	}
	slices.Sort(environment)
	return environment
}

// stopChild settles child within a fresh settlement budget, joining cause so a
// teardown a failure triggered reports both.
func stopChild(parent context.Context, child *daemonkit.Child, cause error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), childSettlementTimeout)
	defer cancel()
	_, err := child.Stop(ctx)
	return errors.Join(cause, err)
}

// closed adapts a child's single-delivery terminal to a channel every watcher
// can select on, which is the shape the daemon's session watchers hold.
func closed(child *daemonkit.Child) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		<-child.Done()
		close(done)
	}()
	return done
}
