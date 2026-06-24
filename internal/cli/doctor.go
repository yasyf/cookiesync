package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/helper"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/service"
	"github.com/yasyf/cookiesync/internal/state"
)

// vaultName is the Secure-Enclave vault item the contract probe checks for; the helper
// reports its biometry/passcode/vault status on one line.
const vaultName = "cookiesync"

// check is one doctor health check's outcome: a label, whether it passed, and a detail
// line shown after the status.
type check struct {
	label  string
	ok     bool
	detail string
}

// doctorEnv is the set of probes the doctor runs, each returning one check. It is the
// seam tests inject a fake environment through so doctor runs without a signed helper,
// a live daemon, or real LaunchAgents. The zero value is not usable; build it with
// realDoctorEnv.
type doctorEnv struct {
	helper  func(ctx context.Context) check
	socket  func(ctx context.Context) check
	state   func(ctx context.Context) check
	tracked func(ctx context.Context) check
	agents  func(ctx context.Context) check
}

// checks runs every probe in a fixed order so the report is deterministic.
func (e doctorEnv) checks(ctx context.Context) []check {
	return []check{
		e.helper(ctx),
		e.socket(ctx),
		e.state(ctx),
		e.tracked(ctx),
		e.agents(ctx),
	}
}

func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check the signed key helper, the resident daemon, the state, and the installed agents.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDoctor(cmd, realDoctorEnv())
		},
	}
	return cmd
}

// runDoctor runs every health check, prints one OK/FAIL line each with its detail, and
// returns a non-empty error (exit 1) when any check failed — matching the Python
// doctor's exit-0-on-success, raise-on-failure behavior, broadened to the full set.
func runDoctor(cmd *cobra.Command, env doctorEnv) error {
	checks := env.checks(cmd.Context())
	failed := 0
	for _, c := range checks {
		status := "OK"
		if !c.ok {
			status = "FAIL"
			failed++
		}
		cmd.Printf("%-4s %s: %s\n", status, c.label, c.detail)
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d checks failed", failed, len(checks))
	}
	return nil
}

// realDoctorEnv wires the production health checks.
func realDoctorEnv() doctorEnv {
	return doctorEnv{
		helper:  checkHelper,
		socket:  checkSocket,
		state:   checkState,
		tracked: checkTracked,
		agents:  checkAgents,
	}
}

// checkHelper confirms the signed key helper is installed and supports the key-helper
// contract. It resolves the helper (failing closed when absent, like the Python
// HelperState.MISSING), then runs the read-only vault-status probe: exit 0 or 2 with a
// "biometry=… passcode=… vault=…" line means the contract is supported; a stale helper
// (no such line) fails. Mirrors the Python doctor's signature + contract check.
func checkHelper(ctx context.Context) check {
	binary, err := paths.RequireHelper()
	if err != nil {
		return check{label: "key helper", detail: err.Error()}
	}
	res, err := helper.Bridge{}.VaultStatus(ctx, vaultName)
	if err != nil {
		return check{label: "key helper", detail: fmt.Sprintf("present at %s but the contract probe failed: %v", binary, err)}
	}
	if !strings.Contains(string(res.Stdout), "vault=") {
		return check{label: "key helper", detail: fmt.Sprintf("present at %s but does not support the key-helper contract (stale cask); reinstall via 'cookiesync install'", binary)}
	}
	return check{label: "key helper", ok: true, detail: fmt.Sprintf("%s (Developer ID signed, key-helper contract supported)", binary)}
}

// checkSocket confirms the resident daemon's RPC socket is bound and accepting — the
// "is the daemon running?" check. A dial that connects means the watch daemon is up.
func checkSocket(ctx context.Context) check {
	sock, err := paths.SockPath()
	if err != nil {
		return check{label: "daemon socket", detail: err.Error()}
	}
	var d net.Dialer
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := d.DialContext(dialCtx, "unix", sock)
	if err != nil {
		return check{label: "daemon socket", detail: fmt.Sprintf("not reachable at %s; run 'cookiesync install' to start the watch daemon", sock)}
	}
	_ = conn.Close()
	return check{label: "daemon socket", ok: true, detail: sock}
}

// checkState confirms cookiesync's state.json parses, so a malformed file is caught
// before a sync trips on it.
func checkState(ctx context.Context) check {
	if _, err := state.New(paths.Config).Load(ctx); err != nil {
		return check{label: "state", detail: err.Error()}
	}
	return check{label: "state", ok: true, detail: "readable"}
}

// checkTracked confirms at least one browser endpoint is registered, since a sync with
// no tracked endpoints does nothing.
func checkTracked(ctx context.Context) check {
	st, err := state.New(paths.Config).Load(ctx)
	if err != nil {
		return check{label: "browsers", detail: err.Error()}
	}
	n := len(st.Endpoints())
	if n == 0 {
		return check{label: "browsers", detail: "no browser endpoints tracked; run 'cookiesync browser add'"}
	}
	return check{label: "browsers", ok: true, detail: fmt.Sprintf("%d tracked", n)}
}

// checkAgents confirms both LaunchAgent plists are installed, the proxy for the agents
// being loaded. A missing plist means install never ran (or was undone). It checks the
// files rather than shelling launchctl so the check is deterministic and side-effect
// free.
func checkAgents(_ context.Context) check {
	dir, err := launchAgentsDir()
	if err != nil {
		return check{label: "agents", detail: err.Error()}
	}
	var missing []string
	for _, label := range []string{service.TickLabel, service.WatchLabel} {
		plist := filepath.Join(dir, label+".plist")
		if info, statErr := os.Stat(plist); statErr != nil || info.IsDir() {
			missing = append(missing, label)
		}
	}
	if len(missing) > 0 {
		return check{label: "agents", detail: fmt.Sprintf("not installed: %s; run 'cookiesync install'", strings.Join(missing, ", "))}
	}
	return check{label: "agents", ok: true, detail: "reconcile tick and watch daemon installed"}
}

// noteHelper prints a one-line note on the signed key helper before install proceeds,
// mirroring the Python ensure_helper's status line. It never fetches or blocks: a
// missing helper is reported, and the agents install anyway (they fail closed at
// runtime without it).
func noteHelper(cmd *cobra.Command) {
	if binary, err := paths.RequireHelper(); err == nil {
		cmd.Printf("Key helper present: %s\n", binary)
		return
	}
	cmd.PrintErrln("Key helper not installed; install it via Homebrew: brew install yasyf/tap/cookiesync-keyhelper")
}

// launchAgentsDir is the user's LaunchAgents directory, where the plists are written.
func launchAgentsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, "Library", "LaunchAgents"), nil
}
