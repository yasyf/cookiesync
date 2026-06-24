// Package service manages the two macOS LaunchAgents that drive cookiesync: a
// periodic reconcile tick and a long-lived watch daemon. The generic
// launchd/launchctl machinery — deterministic plist rendering, the launchctl
// boundary, install/uninstall ordering — lives in the public
// github.com/yasyf/synckit/service package; this package supplies cookiesync's
// ToolConfig (labels, verbs, schedule, the Aqua session limit the keychain-touching
// daemon needs) and delegates to it.
package service

import (
	"context"

	"github.com/yasyf/synckit/service"
)

const (
	// TickLabel is the launchd label for the periodic reconcile tick.
	TickLabel = labelPrefix + "." + reconcileSuffix
	// WatchLabel is the launchd label for the long-lived watch daemon.
	WatchLabel = labelPrefix + "." + watchSuffix

	labelPrefix     = "com.github.yasyf.cookiesync"
	reconcileSuffix = "reconcile"
	watchSuffix     = "watch"

	tickLogRelpath  = "Library/Logs/cookiesync.log"
	watchLogRelpath = "Library/Logs/cookiesync-watch.log"

	// reconcileInterval is the reconcile tick's period in seconds (15 minutes),
	// matching the default settings interval and the Python service.
	reconcileInterval = 900

	// sessionType pins both agents to the Aqua GUI session: the consent layer needs
	// keychain and Touch ID, which are only reachable from the GUI session, so the
	// daemon would be refused the Safe Storage key in a non-Aqua context.
	sessionType = "Aqua"
)

// Launcher bootstraps and boots out launchd jobs; the launchctl boundary tests inject.
type Launcher = service.Launcher

// NewLauncher returns the default Launcher backed by the launchctl CLI.
func NewLauncher() Launcher {
	return service.NewLauncher()
}

// config is cookiesync's launchd job set: the reconcile tick (every reconcileInterval
// seconds, Aqua so a tick can prime a routed key) and the watch daemon (kept alive,
// Aqua for the consent layer). Per-agent log files keep cookiesync's names.
func config() service.ToolConfig {
	return service.ToolConfig{
		BinaryName:  "cookiesync",
		LabelPrefix: labelPrefix,
		DaemonPATH:  service.DefaultDaemonPATH,
		LogName:     logName,
		Agents: []service.AgentSpec{
			{Label: reconcileSuffix, Command: "reconcile", ExtraKeys: map[string]any{
				"StartInterval":          reconcileInterval,
				"RunAtLoad":              true,
				"ProcessType":            "Background",
				"LimitLoadToSessionType": sessionType,
			}},
			{Label: watchSuffix, Command: "watch", ExtraKeys: map[string]any{
				"KeepAlive":              true,
				"RunAtLoad":              true,
				"ProcessType":            "Background",
				"LimitLoadToSessionType": sessionType,
			}},
		},
	}
}

func logName(label string) string {
	switch label {
	case WatchLabel:
		return watchLogRelpath
	default:
		return tickLogRelpath
	}
}

// Config returns cookiesync's launchd job set, exposed so tests assert the rendered
// plists without re-deriving the agent specs.
func Config() service.ToolConfig { return config() }

// Install writes the reconcile tick plist and bootstraps it, and unless tickOnly does
// the same for the watch daemon. Each agent is booted out before bootstrap so a
// re-install picks up plist changes. The launcher is the launchctl boundary tests
// inject so install never loads a real agent.
func Install(ctx context.Context, l Launcher, tickOnly bool) error {
	return service.NewLaunchdManager(l).Install(ctx, config(), tickOnly)
}

// Uninstall boots out both LaunchAgents and removes their plist files; a missing file
// is not an error.
func Uninstall(ctx context.Context, l Launcher) error {
	return service.NewLaunchdManager(l).Uninstall(ctx, config())
}
