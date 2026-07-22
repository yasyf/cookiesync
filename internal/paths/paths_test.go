package paths

import (
	"path/filepath"
	"testing"
)

// TestConfigDirOverrideReachesStateConfig proves ConfigDirEnv is wired into the Config
// var every consumer drives — state.New(Config) resolves its state.json through it — not
// a decorative Dir wrapper: a set override pins Dir and Path verbatim, and an unset
// override falls back to the XDG path.
func TestConfigDirOverrideReachesStateConfig(t *testing.T) {
	root := t.TempDir()
	override := filepath.Join(root, "override")
	xdg := filepath.Join(root, "xdg")
	t.Setenv("XDG_CONFIG_HOME", xdg)

	t.Setenv(ConfigDirEnv, override)
	got, err := Config.Dir()
	if err != nil {
		t.Fatalf("Config.Dir with override: %v", err)
	}
	if got != override {
		t.Fatalf("Config.Dir() = %q, want override %q", got, override)
	}
	path, err := Config.Path()
	if err != nil {
		t.Fatalf("Config.Path with override: %v", err)
	}
	if want := filepath.Join(override, "state.json"); path != want {
		t.Fatalf("Config.Path() = %q, want %q under the override", path, want)
	}

	t.Setenv(ConfigDirEnv, "")
	fallback, err := Config.Dir()
	if err != nil {
		t.Fatalf("Config.Dir without override: %v", err)
	}
	if want := filepath.Join(xdg, ToolName); fallback != want {
		t.Fatalf("Config.Dir() with override unset = %q, want XDG path %q", fallback, want)
	}
}

func TestBridgeRecoveryPathsAreExactUnderConfig(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cookiesync")
	t.Setenv(ConfigDirEnv, root)

	recovery, err := BridgeRecoveryRoot()
	if err != nil {
		t.Fatalf("BridgeRecoveryRoot: %v", err)
	}
	store, err := BridgeProcessStorePath()
	if err != nil {
		t.Fatalf("BridgeProcessStorePath: %v", err)
	}
	sessions, err := BridgeSessionsRoot()
	if err != nil {
		t.Fatalf("BridgeSessionsRoot: %v", err)
	}
	if recovery != filepath.Join(root, "bridge") ||
		store != filepath.Join(root, "bridge", "processes.db") ||
		sessions != filepath.Join(root, "bridge", "sessions") {
		t.Fatalf("bridge paths = recovery %q store %q sessions %q", recovery, store, sessions)
	}
}
