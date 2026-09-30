//go:build darwin

package daemon

import synckit "github.com/yasyf/synckit/rpc"

func (*Daemon) registerPlatform(*synckit.Dispatcher) {}
