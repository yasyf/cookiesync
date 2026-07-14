package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/helper"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/rpc"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/manifest"
	"github.com/yasyf/synckit/syncservice"
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

// doctorEnv is the set of probes the doctor runs. The TCC probe may be inapplicable; all
// others return one check. Tests inject this seam so doctor runs without a signed helper,
// a live helper, or a registered mesh. The zero value is not usable; build it with
// realDoctorEnv.
type doctorEnv struct {
	helper     func(ctx context.Context) check
	socket     func(ctx context.Context) check
	keyCache   func(ctx context.Context) check
	mesh       func(ctx context.Context) check
	tcc        func(ctx context.Context) (check, bool)
	manifest   func(ctx context.Context) check
	state      func(ctx context.Context) check
	tracked    func(ctx context.Context) check
	quarantine func(ctx context.Context) []check
}

// checks runs every probe in a fixed order so the report is deterministic.
func (e doctorEnv) checks(ctx context.Context) []check {
	checks := []check{
		e.helper(ctx),
		e.socket(ctx),
		e.keyCache(ctx),
		e.mesh(ctx),
	}
	if tcc, ok := e.tcc(ctx); ok {
		checks = append(checks, tcc)
	}
	checks = append(checks,
		e.manifest(ctx),
		e.state(ctx),
		e.tracked(ctx),
	)
	return append(checks, e.quarantine(ctx)...)
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
		keyCache: checkKeyCache,
		mesh:     checkMesh,
		tcc: func(ctx context.Context) (check, bool) {
			return checkTCC(ctx, mesh.Resolve)
		},
		manifest:   checkManifest,
		state:      checkState,
		tracked:    checkTracked,
		quarantine: checkQuarantine,
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

// checkSocket confirms the resident helper's RPC socket is bound AND speaks the typed
// sync contract synckitd drives — the "is the helper up and serving svc.*?" check. It
// dials the socket and round-trips svc.capabilities, the lightest typed call (no cookie
// store read, no SE key), so a green line proves the contract is live end to end through
// the same socket synckitd's rpc-serve bridge forwards to.
func checkSocket(ctx context.Context) check {
	sock, err := paths.SockPath()
	if err != nil {
		return check{label: "helper socket", detail: err.Error()}
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	client := syncservice.NewClient(syncservice.Socket(sock))
	defer func() { _ = client.Close() }()
	caps, err := client.Capabilities(probeCtx)
	if err != nil {
		return check{label: "helper socket", detail: fmt.Sprintf("not serving the typed contract at %s; run 'synckitd install' to start the resident helper (cookiesync helper-serve): %v", sock, err)}
	}
	return check{label: "helper socket", ok: true, detail: fmt.Sprintf("%s (svc protocol v%d)", sock, caps.ProtocolVersion)}
}

// keyCacheStatus is the slice of the auth_status reply the key-cache check reads: the
// cache-global degradation flag and whether the daemon user's keybag is unavailable
// (screen locked, session absent, or held by another user). A locked keybag makes an
// in-memory degradation and an Enclave unavailability expected, healthy states.
type keyCacheStatus struct {
	Degraded bool `json:"degraded"`
	Locked   bool `json:"keybag_locked"`
}

// checkKeyCache confirms the resident daemon's current key-cache wrapping state. The
// flags are cache-global, so the probe reads them off auth_status for the default chrome
// endpoint — the endpoint itself is immaterial — and keyCacheCheck renders them.
func checkKeyCache(ctx context.Context) check {
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var status keyCacheStatus
	if err := rpc.CallJSON(probeCtx, "auth_status", map[string]any{"browser": "chrome"}, &status); err != nil {
		return check{label: "key cache", detail: fmt.Sprintf("auth_status probe failed: %v", err)}
	}
	return keyCacheCheck(status)
}

// keyCacheCheck renders the key-cache health line from the daemon's degradation and
// keybag-availability flags. The cache may demote and re-heal during the daemon's life. A
// locked keybag makes either state expected; only an in-memory cache while the keybag is
// available is a genuine FAIL.
func keyCacheCheck(status keyCacheStatus) check {
	switch {
	case status.Degraded && status.Locked:
		return check{label: "key cache", ok: true, detail: "in process memory (keybag locked; re-heals Secure-Enclave wrapped on the next authorization)"}
	case status.Degraded:
		return check{label: "key cache", detail: "degraded after a Secure Enclave presence refusal; run 'cookiesync auth' to re-prime"}
	case status.Locked:
		return check{label: "key cache", ok: true, detail: "Secure-Enclave wrapped (keybag locked: screen locked or session away)"}
	default:
		return check{label: "key cache", ok: true, detail: "Secure-Enclave wrapped"}
	}
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

// checkTCC emits an informational peer-access pointer when cross-host pulls apply. It
// never fails because a TCC denial cannot be confirmed without Full Disk Access.
func checkTCC(ctx context.Context, resolve func(context.Context) (string, []string, error)) (check, bool) {
	_, peers, err := resolve(ctx)
	if err != nil || len(peers) == 0 {
		return check{}, false
	}
	return check{
		label:  "peer TCC",
		ok:     true,
		detail: "cross-host pulls use ssh; if this host times out pulling from a peer, check Full Disk Access for the peer's ssh identity (sshd or tailscaled)",
	}, true
}

// checkManifest confirms cookiesync's synckit manifest is registered AND validates
// against the current schema — the typed service block synckitd drives, not the old
// action templates — so a stale manifest from a prior install is caught. A missing
// manifest means 'cookiesync install' never ran; a manifest that no longer validates
// means 're-run cookiesync install'. manifest.Load both decodes and validates.
func checkManifest(_ context.Context) check {
	path, err := manifestPath()
	if err != nil {
		return check{label: "manifest", detail: err.Error()}
	}
	if info, statErr := os.Stat(path); statErr != nil || info.IsDir() {
		return check{label: "manifest", detail: fmt.Sprintf("not registered at %s; run 'cookiesync install'", path)}
	}
	m, err := manifest.Load(path)
	if err != nil {
		return check{label: "manifest", detail: fmt.Sprintf("registered at %s but does not validate (stale schema); re-run 'cookiesync install': %v", path, err)}
	}
	if m.Service.Transport != "socket" {
		return check{label: "manifest", detail: fmt.Sprintf("service transport = %q at %s, want socket; re-run 'cookiesync install'", m.Service.Transport, path)}
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

// checkQuarantine emits one failing line per endpoint the mass-drop quarantine holds
// out of the merge, read from the persisted rowcount baselines. A healthy host emits
// nothing.
func checkQuarantine(ctx context.Context) []check {
	st, err := state.New(paths.Config).Load(ctx)
	if err != nil {
		return []check{{label: "quarantine", detail: err.Error()}}
	}
	return quarantineChecks(st.Baselines)
}

// quarantineChecks renders one FAIL line per quarantined endpoint, sorted by id.
func quarantineChecks(baselines map[string]state.Baseline) []check {
	ids := make([]string, 0, len(baselines))
	for id, baseline := range baselines {
		if baseline.Quarantined {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	checks := make([]check, 0, len(ids))
	for _, id := range ids {
		baseline := baselines[id]
		recoverRows := int(float64(baseline.Rows) * engine.QuarantineRecoverFraction)
		checks = append(checks, check{
			label: "quarantine",
			detail: fmt.Sprintf("%s: rowcount collapsed to %d vs baseline %d; excluded from merge inputs until it recovers to >= %d rows",
				id, baseline.QuarantinedRows, baseline.Rows, recoverRows),
		})
	}
	return checks
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
