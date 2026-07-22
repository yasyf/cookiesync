// Package paths resolves cookiesync's on-disk locations: the per-tool config
// directory and the resident daemon's RPC unix socket, both under
// XDG_CONFIG_HOME (or ~/.config). It forwards to the shared
// github.com/yasyf/synckit/hostregistry primitives so cookiesync and reposync
// agree on the config-dir convention.
package paths

import (
	"path/filepath"

	"github.com/yasyf/synckit/hostregistry"
)

// ToolName is cookiesync's CLI/config identity: it selects ~/.config/cookiesync
// and is the single source for the hostregistry Config the path helpers drive.
const ToolName = "cookiesync"

// ConfigDirEnv is the environment variable that pins cookiesync's config directory
// verbatim when set; it threads into Config so every consumer, state.New(Config)
// included, honors the override, while the shared synckit mesh is left in place.
const ConfigDirEnv = "COOKIESYNC_CONFIG_DIR"

// Config is cookiesync's host-registry handle, naming the tool so hostregistry
// resolves the config dir and the daemon socket path, with ConfigDirEnv as the
// per-tool config-dir override.
var Config = hostregistry.Config{Name: ToolName, DirEnv: ConfigDirEnv}

// Dir returns cookiesync's config directory (~/.config/cookiesync).
func Dir() (string, error) {
	return Config.Dir()
}

// SockPath returns the absolute path to the resident daemon's RPC unix socket
// (~/.config/cookiesync/rpc.sock).
func SockPath() (string, error) {
	return Config.SockPath()
}

// BridgeRecoveryRoot returns the v1 bridge process-liability root.
func BridgeRecoveryRoot() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "bridge"), nil
}

// BridgeProcessStorePath returns the daemonkit process and receipt ledger.
func BridgeProcessStorePath() (string, error) {
	root, err := BridgeRecoveryRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "processes.db"), nil
}

// BridgeSessionsRoot returns the root for derived bridge session state.
func BridgeSessionsRoot() (string, error) {
	root, err := BridgeRecoveryRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "sessions"), nil
}
