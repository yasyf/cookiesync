package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/helper"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/paths"
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
// a live helper, or a registered mesh. The zero value is not usable; build it with
// realDoctorEnv.
type doctorEnv struct {
	helper   func(ctx context.Context) check
	socket   func(ctx context.Context) check
	mesh     func(ctx context.Context) check
	manifest func(ctx context.Context) check
	state    func(ctx context.Context) check
	tracked  func(ctx context.Context) check
}

// checks runs every probe in a fixed order so the report is deterministic.
func (e doctorEnv) checks(ctx context.Context) []check {
	return []check{
		e.helper(ctx),
		e.socket(ctx),
		e.mesh(ctx),
		e.manifest(ctx),
		e.state(ctx),
		e.tracked(ctx),
	}
}

func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check the signed key helper, the resident helper, the synckit mesh and manifest, and the state.",
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
		helper:   checkHelper,
		socket:   checkSocket,
		mesh:     checkMesh,
		manifest: checkManifest,
		state:    checkState,
		tracked:  checkTracked,
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

// checkSocket confirms the resident helper's RPC socket is bound and accepting — the
// "is the helper running?" check. A dial that connects means the resident helper
// (cookiesync helper-serve) is up.
func checkSocket(ctx context.Context) check {
	sock, err := paths.SockPath()
	if err != nil {
		return check{label: "helper socket", detail: err.Error()}
	}
	var d net.Dialer
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := d.DialContext(dialCtx, "unix", sock)
	if err != nil {
		return check{label: "helper socket", detail: fmt.Sprintf("not reachable at %s; run 'synckitd install' to start the resident helper (cookiesync helper-serve)", sock)}
	}
	_ = conn.Close()
	return check{label: "helper socket", ok: true, detail: sock}
}

// checkMesh confirms this host has joined the synckit host mesh — that the shared
// registry reports a self target. cookiesync keys every endpoint and converges across
// the mesh, so an unjoined host syncs nothing.
func checkMesh(ctx context.Context) check {
	self, _, err := mesh.Resolve(ctx)
	if err != nil {
		return check{label: "mesh", detail: err.Error()}
	}
	return check{label: "mesh", ok: true, detail: fmt.Sprintf("self %s", self)}
}

// checkManifest confirms cookiesync's synckit manifest is registered, so synckitd
// discovers and drives it. A missing manifest means 'cookiesync install' never ran.
func checkManifest(_ context.Context) check {
	path, err := manifestPath()
	if err != nil {
		return check{label: "manifest", detail: err.Error()}
	}
	if info, statErr := os.Stat(path); statErr != nil || info.IsDir() {
		return check{label: "manifest", detail: fmt.Sprintf("not registered at %s; run 'cookiesync install'", path)}
	}
	return check{label: "manifest", ok: true, detail: path}
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

// noteHelper prints a one-line note on the signed key helper before install proceeds,
// mirroring the Python ensure_helper's status line. It never fetches or blocks: a
// missing helper is reported, and the manifest registers anyway (the helper fails closed
// at runtime without it).
func noteHelper(cmd *cobra.Command) {
	if binary, err := paths.RequireHelper(); err == nil {
		cmd.Printf("Key helper present: %s\n", binary)
		return
	}
	cmd.PrintErrln("Key helper not installed; install it via Homebrew: brew install yasyf/tap/cookiesync-keyhelper")
}
