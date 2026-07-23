// Package tui is the interactive terminal UI launched by bare `cookiesync` on a
// TTY: a Browsers tab for tracking cookie profiles plus the shared Hosts tab the
// synckit TUI appends for managing the mesh.
package tui

import (
	"context"

	"github.com/yasyf/synckit/hostregistry"
	stui "github.com/yasyf/synckit/tui"
)

// Run launches the interactive TUI and blocks until the user quits or ctx is
// canceled. It mounts the Browsers content screen and lets the shared synckit TUI
// append the Hosts tab. A ctx-driven teardown (ctrl-c, SIGTERM) is a clean exit.
func Run(ctx context.Context, version string) error {
	return hostregistry.WithExecRunner(ctx, func(runner hostregistry.Runner) error {
		return stui.Run(ctx, stui.Options{
			Brand:   "cookiesync",
			Version: version,
			Screens: []stui.Screen{newBrowsersModel(runner)},
			Runner:  runner,
		})
	})
}
