// Package paths resolves cookiesync's on-disk locations: the per-tool config
// directory and the resident daemon's RPC unix socket, both under
// XDG_CONFIG_HOME (or ~/.config). It forwards to the shared
// github.com/yasyf/synckit/hostregistry primitives so cookiesync and reposync
// agree on the config-dir convention.
package paths

import "github.com/yasyf/synckit/hostregistry"

// ToolName is cookiesync's CLI/config identity: it selects ~/.config/cookiesync
// and is the single source for the hostregistry Config the path helpers drive.
const ToolName = "cookiesync"

// Config is cookiesync's host-registry handle, naming the tool so hostregistry
// resolves the config dir and the daemon socket path.
var Config = hostregistry.Config{Name: ToolName}

// Dir returns cookiesync's config directory (~/.config/cookiesync).
func Dir() (string, error) {
	return Config.Dir()
}

// SockPath returns the absolute path to the resident daemon's RPC unix socket
// (~/.config/cookiesync/rpc.sock).
func SockPath() (string, error) {
	return Config.SockPath()
}
